import datetime
import email.utils
import hashlib
import secrets
from typing import Sequence, Type, Union

import http_sfv
import requests
from http_message_signatures import (  # noqa: F401
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    algorithms,
)
from http_message_signatures.structures import CaseInsensitiveDict, VerifyResult
from requests.exceptions import RequestException


class RequestsHttpSignatureException(RequestException):
    """An error occurred while constructing the HTTP Signature for your request."""


class SingleKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id, key):
        self.key_id = key_id
        self.key = key

    def resolve_public_key(self, key_id):
        assert key_id == self.key_id
        return self.key

    def resolve_private_key(self, key_id):
        assert key_id == self.key_id
        return self.key


class HTTPSignatureAuth(requests.auth.AuthBase):
    """
    A `Requests <https://github.com/requests/requests>`_ `authentication plugin
    <http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass)
    implementing the `IETF HTTP Message Signatures draft RFC
    <https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/>`_.

    :param signature_algorithm:
        One of ``requests_http_signature.algorithms.HMAC_SHA256``,
        ``requests_http_signature.algorithms.ECDSA_P256_SHA256``,
        ``requests_http_signature.algorithms.ED25519``,
        ``requests_http_signature.algorithms.RSA_PSS_SHA512``, or
        ``requests_http_signature.algorithms.RSA_V1_5_SHA256``.
    :param key:
        Key material that will be used to sign the request. In the case of HMAC, this should be the raw bytes of the
        shared secret; for all other algorithms, this should be the bytes of the PEM-encoded private key material.
    :param key_id: The key ID to use in the signature.
    :param key_resolver:
        Instead of specifying a fixed key, you can instead pass a key resolver, which should be an instance of a
        subclass of ``http_message_signatures.HTTPSignatureKeyResolver``. A key resolver should have two methods,
        ``get_private_key(key_id)`` (required only for signing) and ``get_public_key(key_id)`` (required only for
        verifying). Your implementation should ensure that the key id is recognized and return the corresponding
        key material as PEM bytes (or shared secret bytes for HMAC).
    :param covered_component_ids:
        A list of lowercased header names or derived component IDs (``@method``, ``@target-uri``, ``@authority``,
        ``@scheme``, ``@request-target``, ``@path``, ``@query``, ``@query-params``, ``@status``, or
        ``@request-response``, as specified in the standard) to sign. By default, ``@method``, ``@authority``,
        and ``@target-uri`` are covered, and the ``Authorization``, ``Content-Digest``, and ``Date`` header fields
        are always covered if present.
    :param label: The label to use to identify the signature.
    :param include_alg:
        By default, the signature parameters will include the ``alg`` parameter, using it to identify the signature
        algorithm. If you wish not to include this parameter, set this to ``False``.
    :param use_nonce:
        Set this to ``True`` to include a unique message-specific nonce in the signature parameters. The format of
        the nonce can be controlled by subclassing this class and overloading the ``get_nonce()`` method.
    :param expires_in:
        Use this to set the ``expires`` signature parameter to the time of signing plus the given timedelta.
    """

    component_resolver_class: type = HTTPSignatureComponentResolver
    """
    A subclass of ``http_message_signatures.HTTPSignatureComponentResolver`` can be used to override this value
    to customize the retrieval of header and derived component values if needed.
    """

    _content_digest_hashers = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
    signing_content_digest_algorithm = "sha-256"
    "The hash algorithm to use to generate the Content-Digest header field (either ``sha-256`` or ``sha-512``)."

    _auto_cover_header_fields = {"authorization", "content-digest", "date"}

    def __init__(self, *,
                 signature_algorithm: Type[HTTPSignatureAlgorithm],
                 key: bytes = None,
                 key_id: str,
                 key_resolver: HTTPSignatureKeyResolver = None,
                 covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
                 label: str = None,
                 include_alg: bool = True,
                 use_nonce: bool = False,
                 expires_in: datetime.timedelta = None):
        if key_resolver is None and key is None:
            raise RequestsHttpSignatureException("Either key_resolver or key must be specified.")
        if key_resolver is not None and key is not None:
            raise RequestsHttpSignatureException("Either key_resolver or key must be specified, not both.")
        if key_resolver is None:
            key_resolver = SingleKeyResolver(key_id=key_id, key=key)

        self.key_id = key_id
        self.label = label
        self.include_alg = include_alg
        self.use_nonce = use_nonce
        self.covered_component_ids = covered_component_ids
        self.expires_in = expires_in
        self.signer = HTTPMessageSigner(signature_algorithm=signature_algorithm,
                                        key_resolver=key_resolver,
                                        component_resolver_class=self.component_resolver_class)

    def add_date(self, request, timestamp):
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def add_digest(self, request):
        if request.body is None and "content-digest" in self.covered_component_ids:
            raise RequestsHttpSignatureException("Could not compute digest header for request without a body")
        if request.body is not None:
            if "Content-Digest" not in request.headers:
                hasher = self._content_digest_hashers[self.signing_content_digest_algorithm]
                digest = hasher(request.body).digest()
                digest_node = http_sfv.Dictionary({self.signing_content_digest_algorithm: digest})
                request.headers["Content-Digest"] = str(digest_node)

    def get_nonce(self, request):
        if self.use_nonce:
            return secrets.token_urlsafe(16)

    def get_created(self, request):
        created = datetime.datetime.now()
        self.add_date(request, timestamp=int(created.timestamp()))
        return created

    def get_expires(self, request, created):
        if self.expires_in:
            return datetime.datetime.now() + self.expires_in

    def get_covered_component_ids(self, request):
        covered_component_ids = CaseInsensitiveDict((k, None) for k in self.covered_component_ids)
        headers = CaseInsensitiveDict(request.headers)
        for header in self._auto_cover_header_fields:
            if header in headers:
                covered_component_ids.setdefault(header, None)
        return list(covered_component_ids)

    def __call__(self, request):
        self.add_digest(request)
        created = self.get_created(request)
        expires = self.get_expires(request, created=created)
        covered_component_ids = self.get_covered_component_ids(request)
        self.signer.sign(request,
                         key_id=self.key_id,
                         created=created,
                         expires=expires,
                         nonce=self.get_nonce(request),
                         label=self.label,
                         include_alg=self.include_alg,
                         covered_component_ids=covered_component_ids)
        return request

    @classmethod
    def get_body(cls, message):
        if isinstance(message, requests.Response):
            return message.content
        return message.body

    @classmethod
    def verify(cls, message: Union[requests.PreparedRequest, requests.Response], *,
               require_components: Sequence[str] = ("@method", "@authority", "@target-uri"),
               signature_algorithm: Type[HTTPSignatureAlgorithm],
               key_resolver: HTTPSignatureKeyResolver,
               max_age: datetime.timedelta = datetime.timedelta(days=1)) -> VerifyResult:
        """
        Verify an HTTP message signature.

        .. admonition:: See what is signed

         It is important to understand and follow the best practice rule of "See what is signed" when verifying HTTP
         message signatures. The gist of this rule is: if your application neglects to verify that the information it
         trusts is what was actually signed, the attacker can supply a valid signature but point you to malicious data
         that wasn't signed by that signature. Failure to follow this rule can lead to vulnerability against signature
         wrapping and substitution attacks.

         You can ensure that the information signed is what you expect to be signed by only trusting the *VerifyResult*
         tuple returned by ``verify()``.

        :param message:
            The HTTP response or request to verify. You can either pass a received response, or reconstruct an arbitrary
            request using the `Requests API <https://docs.python-requests.org/en/latest/api/#requests.Request>`_::

              request = requests.Request(...)
              prepared_request = request.prepare()
              HTTPSignatureAuth.verify(prepared_request, ...)

        :param require_components:
            A list of lowercased header names or derived component IDs (``@method``, ``@target-uri``, ``@authority``,
            ``@scheme``, ``@request-target``, ``@path``, ``@query``, ``@query-params``, ``@status``, or
            ``@request-response``, as specified in the standard) to require to be covered by the signature. If the
            ``content-digest`` header field is specified here (recommended for messages that have a body), it will be
            verified by matching it against the digest hash computed on the body of the message (expected to be bytes).

            If this parameter is not specified, ``verify()`` will set it to ``("@method", "@authority", "@target-uri")``
            for messages without a body, and ``("@method", "@authority", "@target-uri", "content-digest")`` for messages
            with a body.
        :param signature_algorithm:
            The algorithm expected to be used by the signature. Any signature not using the expected algorithm will
            cause an ``InvalidSignature`` exception. Must be one of ``requests_http_signature.algorithms.HMAC_SHA256``,
            ``requests_http_signature.algorithms.ECDSA_P256_SHA256``,
            ``requests_http_signature.algorithms.ED25519``,
            ``requests_http_signature.algorithms.RSA_PSS_SHA512``, or
            ``requests_http_signature.algorithms.RSA_V1_5_SHA256``.
        :param key_resolver:
            A key resolver, which should be an instance of a subclass of
            ``http_message_signatures.HTTPSignatureKeyResolver``. A key resolver should have two methods,
            ``get_private_key(key_id)`` (required only for signing) and ``get_public_key(key_id)`` (required only for
            verifying). Your implementation should ensure that the key id is recognized and return the corresponding
            key material as PEM bytes (or shared secret bytes for HMAC).
        :param max_age:
            The maximum age of the signature, defined as the difference between the ``created`` parameter value and now.

        :returns: *VerifyResult*, a namedtuple with the following attributes:

            * ``label`` (str): The label for the signature
            * ``algorithm``: (same as ``signature_algorithm`` above)
            * ``covered_components``: A mapping of component names to their values, as covered by the signature
            * ``parameters``: A mapping of signature parameters to their values, as covered by the signature, including
              "alg", "created", "expires", "keyid", and "nonce". To protect against replay attacks, retrieve the "nonce"
              parameter here and check that it has not been seen before.
            * ``body``: The message body for messages that have a body and pass validation of the covered
              content-digest; ``None`` otherwise.

        :raises: ``InvalidSignature`` - raised whenever signature validation fails for any reason.
        """
        body = cls.get_body(message)
        if body is not None:
            if "content-digest" not in require_components and '"content-digest"' not in require_components:
                require_components = list(require_components) + ["content-digest"]

        verifier = HTTPMessageVerifier(signature_algorithm=signature_algorithm,
                                       key_resolver=key_resolver,
                                       component_resolver_class=cls.component_resolver_class)
        verify_results = verifier.verify(message, max_age=max_age)
        if len(verify_results) != 1:
            raise InvalidSignature("Multiple signatures are not supported.")
        verify_result = verify_results[0]
        for component_name in require_components:
            component_key = component_name
            if not component_key.startswith('"'):
                component_key = str(http_sfv.List([http_sfv.Item(component_name)]))
            if component_key not in verify_result.covered_components:
                raise InvalidSignature(f"A required component, {component_key}, was not covered by the signature.")
            if component_key == '"content-digest"':
                if body is None:
                    raise InvalidSignature("Found a content-digest header in a message with no body")
                digest = http_sfv.Dictionary()
                digest.parse(verify_result.covered_components[component_key].encode())
                if len(digest) < 1:
                    raise InvalidSignature("Found a content-digest header with no digests")
                for k, v in digest.items():
                    if k not in cls._content_digest_hashers:
                        raise InvalidSignature(f'Unsupported content digest algorithm "{k}"')
                    raw_digest = v.value
                    hasher = cls._content_digest_hashers[k]
                    expect_digest = hasher(body).digest()
                    if raw_digest != expect_digest:
                        raise InvalidSignature("The content-digest header does not match the message body")
                    verify_result = verify_result._replace(body=body)
        return verify_result

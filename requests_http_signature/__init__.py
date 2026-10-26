import datetime
import email.utils
import secrets
from collections.abc import Sequence
from typing import Any, ClassVar

import requests
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    MappingKeyResolver,
)
from http_message_signatures import InvalidSignature as InvalidSignature
from http_message_signatures import PreparedSignature as PreparedSignature
from http_message_signatures import VerifyResult as VerifyResult
from http_message_signatures import algorithms as algorithms
from http_message_signatures.structures import get_header_fields
from requests.exceptions import RequestException


class RequestsHttpSignatureException(RequestException):
    """An error occurred while constructing the HTTP Signature for your request."""


class HTTPSignatureAuth(requests.auth.AuthBase):
    """
    A `Requests <https://github.com/requests/requests>`_ `authentication plugin
    <http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass)
    implementing `RFC 9421, HTTP Message Signatures <https://www.rfc-editor.org/rfc/rfc9421.html>`_.

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
        ``resolve_private_key(key_id)`` (required only for signing) and ``resolve_public_key(key_id)`` (required only for
        verifying). Your implementation should ensure that the key id is recognized and return the corresponding
        key material as PEM bytes, cryptography key objects, or shared secret bytes for HMAC.
        Omit both ``key`` and ``key_resolver`` when using ``prepare()`` and ``apply()`` with an external signer.
    :param covered_component_ids:
        Lowercase header names or serialized RFC 9421 component identifiers. Request derived components include
        ``@method``, ``@target-uri``, ``@authority``, ``@scheme``, ``@request-target``, ``@path``, ``@query``, and
        ``'"@query-param";name="Pet"'``. Parameter values are case-sensitive; their order does not affect identity.
        Duplicate component identifiers are rejected. Defaults to ``@method``, ``@authority``, and ``@target-uri``.
        ``Authorization`` and ``Date`` are also covered when present. The upstream signer adds digest coverage for
        buffered content, including empty requests. Explicit digest-member coverage, such as
        ``'"content-digest";key="sha-256"'``, replaces automatic whole-field coverage for buffered content.
        Streams always cover the whole supplied Content-Digest field.
    :param label: The signature dictionary label, which is not signed.
    :param tag: A signed application tag, usable with ``verify(expect_tag=...)``.
    :param append_if_signature_exists: Append a distinct signature label instead of replacing existing signatures.
    :param include_alg:
        By default, the signature parameters will include the ``alg`` parameter, using it to identify the signature
        algorithm. If you wish not to include this parameter, set this to ``False``.
    :param use_nonce:
        Set this to ``True`` to include a unique message-specific nonce in the signature parameters. The format of
        the nonce can be controlled by subclassing this class and overloading the ``get_nonce()`` method.
    :param expires_in:
        Use this to set the ``expires`` signature parameter to the time of signing plus the given timedelta.
    :param use_existing_digest:
        Allow a supplied Content-Digest, validating it against buffered bytes before signing.
        Required for streams with precomputed digests and when signing a request again.
    """

    component_resolver_class: type[HTTPSignatureComponentResolver] = HTTPSignatureComponentResolver
    """
    A subclass of ``http_message_signatures.HTTPSignatureComponentResolver`` can be used to override this value
    to customize the retrieval of header and derived component values if needed.
    """

    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier
    "A verifier subclass can configure creation-time requirements and clock-skew tolerance."

    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    "A signer subclass can select a ContentDigest subclass through its content_digest_class attribute."

    _auto_cover_header_fields: ClassVar[tuple[str, ...]] = ("authorization", "date")

    @staticmethod
    def _validate_header_names(message: requests.PreparedRequest | requests.Response) -> None:
        seen = set()
        for name in message.headers:
            if name.lower() in seen:
                raise RequestsHttpSignatureException(f"Multiple header values match {name!r} case-insensitively")
            seen.add(name.lower())

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key: bytes | None = None,
        key_id: str,
        key_resolver: HTTPSignatureKeyResolver | None = None,
        covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
        label: str | None = None,
        tag: str | None = None,
        append_if_signature_exists: bool = False,
        include_alg: bool = True,
        use_nonce: bool = False,
        expires_in: datetime.timedelta | None = None,
        use_existing_digest: bool = False,
    ) -> None:
        if key_resolver is not None and key is not None:
            raise RequestsHttpSignatureException("Either key_resolver or key must be specified, not both.")
        if key is not None:
            key_resolver = MappingKeyResolver(private_keys={key_id: key}, public_keys={key_id: key})

        self.key_id = key_id
        self.label = label
        self.tag = tag
        self.append_if_signature_exists = append_if_signature_exists
        self.include_alg = include_alg
        self.use_nonce = use_nonce
        self.covered_component_ids = covered_component_ids
        self.expires_in = expires_in
        self.use_existing_digest = use_existing_digest
        self.signer = self.signer_class(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=self.component_resolver_class,
        )

    def add_date(self, request: requests.PreparedRequest, timestamp: int) -> None:
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def _signing_body(self, request: requests.PreparedRequest) -> bytes | None:
        self._validate_header_names(request)
        request.headers = requests.structures.CaseInsensitiveDict(request.headers)
        if isinstance(request.body, str):
            request.body = request.body.encode("utf-8")
        elif isinstance(request.body, (bytearray, memoryview)):
            request.body = bytes(request.body)
        if request.body is not None and not isinstance(request.body, bytes):
            if "Content-Digest" not in request.headers:
                raise RequestsHttpSignatureException(
                    "Streaming bodies require a precomputed Content-Digest header; the stream is not read or rewound"
                )
            return None
        return request.body or b""

    def get_nonce(self, request: requests.PreparedRequest) -> str | None:
        if self.use_nonce:
            return secrets.token_urlsafe(16)
        return None

    def get_created(self, request: requests.PreparedRequest) -> datetime.datetime:
        created = datetime.datetime.now()
        self.add_date(request, timestamp=int(created.timestamp()))
        return created

    def get_expires(self, request: requests.PreparedRequest, created: datetime.datetime) -> datetime.datetime | None:
        if self.expires_in is not None:
            return created + self.expires_in
        return None

    def get_covered_component_ids(self, request: requests.PreparedRequest) -> Sequence[str]:
        if isinstance(self.covered_component_ids, (str, bytes, bytearray)):
            return self.covered_component_ids
        components = list(self.covered_component_ids)
        auto_cover = self._auto_cover_header_fields
        if request.body is not None and not isinstance(request.body, bytes):
            auto_cover += ("content-digest",)
        for header in auto_cover:
            if header in request.headers and header not in components and f'"{header}"' not in components:
                components.append(header)
        return components

    def _signing_options(self, request: requests.PreparedRequest) -> dict[str, Any]:
        body = self._signing_body(request)
        created = self.get_created(request)
        return {
            "key_id": self.key_id,
            "created": created,
            "expires": self.get_expires(request, created=created),
            "nonce": self.get_nonce(request),
            "label": self.label,
            "tag": self.tag,
            "include_alg": self.include_alg,
            "covered_component_ids": self.get_covered_component_ids(request),
            "body": body,
            "use_existing_digest": self.use_existing_digest,
        }

    def prepare(self, request: requests.PreparedRequest) -> PreparedSignature:
        """Set digest/date headers and return signing input without resolving a key.

        Use a fully prepared Requests request. Keep the returned object with this
        request while an external signer signs its ``signature_base`` bytes.
        """
        return self.signer.prepare(request, **self._signing_options(request))

    def apply(
        self,
        request: requests.PreparedRequest,
        prepared: PreparedSignature,
        signature: bytes,
        *,
        append_if_signature_exists: bool | None = None,
    ) -> requests.PreparedRequest:
        """Attach raw signature bytes and return the request ready for ``Session.send``.

        Covered values must still match preparation. Buffered bodies are checked
        against their digest; callers supplying stream digests must keep the stream
        unchanged. This does not verify the external signature or refresh its age.
        """
        self._validate_header_names(request)
        headers = get_header_fields(request.headers)
        if "Content-Digest" in headers and (
            request.body is None or isinstance(request.body, (str, bytes, bytearray, memoryview))
        ):
            self.signer.content_digest_class.verify(headers["Content-Digest"], self.get_body(request))
        self.signer.apply(
            request,
            prepared,
            signature,
            append_if_signature_exists=(
                self.append_if_signature_exists if append_if_signature_exists is None else append_if_signature_exists
            ),
        )
        return request

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.signer.key_resolver is None:
            raise RequestsHttpSignatureException(
                "Local signing requires a key or key_resolver; use prepare()/apply() otherwise"
            )
        self.signer.sign(
            request,
            append_if_signature_exists=self.append_if_signature_exists,
            **self._signing_options(request),
        )
        return request

    @classmethod
    def get_body(cls, message: requests.PreparedRequest | requests.Response) -> bytes:
        if isinstance(message, requests.Response):
            if (
                message.status_code in (204, 304)
                or 100 <= message.status_code < 200
                or (message.request is not None and message.request.method == "HEAD")
            ):
                return b""
            headers = requests.structures.CaseInsensitiveDict(message.headers)
            if headers.get("Content-Encoding", "identity").lower() != "identity":
                raise InvalidSignature(
                    "Encoded responses require body= with encoded bytes: request stream=True, "
                    "then read response.raw.read(decode_content=False) before accessing response.content"
                )
            return message.content
        if isinstance(message.body, str):
            return message.body.encode("utf-8")
        if isinstance(message.body, (bytes, bytearray, memoryview)):
            return bytes(message.body)
        if message.body is not None:
            raise InvalidSignature("Verifying a streaming request requires body= with the transmitted bytes")
        return b""

    @classmethod
    def verify(
        cls,
        message: requests.PreparedRequest | requests.Response,
        *,
        require_components: Sequence[str] | None = None,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver,
        max_age: datetime.timedelta | None = datetime.timedelta(days=1),
        expect_tag: str | None = None,
        expect_label: str | None = None,
        body: bytes | None = None,
    ) -> VerifyResult:
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
            Lowercase header names or serialized component identifiers whose coverage is required. Parameter order
            is ignored for comparison, but parameter values retain their case and types. Duplicate identifiers fail.
            The request default is ``("@method", "@authority", "@target-uri")``. The response default is
            ``("@status", '"@method";req', '"@authority";req', '"@target-uri";req')``, binding the response to its request.
            Supply a different profile explicitly if your peer signs other components.

            Nonempty content, or a present Content-Digest field, additionally requires a covered content digest.
            A selected digest dictionary member is sufficient. Empty messages do not require an absent digest;
            any present digest is still verified, including the digest of empty content. Request components with
            ``;req`` do not satisfy coverage of the response body. Validation returns the bytes in ``result.body``.
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
            ``resolve_private_key(key_id)`` (required only for signing) and ``resolve_public_key(key_id)`` (required only for
            verifying). Your implementation should ensure that the key id is recognized and return the corresponding
            key material as PEM bytes (or shared secret bytes for HMAC).
        :param max_age:
            Maximum age since ``created``; ``None`` disables this limit, but expiration is still checked.
            Customize ``verifier_class`` to change its ``require_created`` and ``max_clock_skew`` policies.
        :param expect_tag: Select a signed application tag. Selection must leave one verified signature.
        :param expect_label: Further select the dictionary label; requires ``expect_tag`` under the default policy.
        :param body:
            Transmitted content bytes before content decoding. Required for compressed responses and streaming
            request bodies. For a compressed response, send with ``stream=True`` and capture
            ``response.raw.read(decode_content=False)`` before accessing ``response.content`` or ``iter_content()``.
            This method does not check that caller-supplied bytes came from the message; keep that association intact.
            Without this argument, unencoded response content is read into memory and buffered request bodies are used.

        :returns: *VerifyResult*, a namedtuple with the following attributes:

            * ``label`` (str): The label for the signature
            * ``algorithm``: (same as ``signature_algorithm`` above)
            * ``covered_components``: A mapping of component names to their values, as covered by the signature
            * ``parameters``: A mapping of signature parameters to their values, as covered by the signature, including
              "alg", "created", "expires", "keyid", and "nonce". To protect against replay attacks, retrieve the "nonce"
              parameter here and check that it has not been seen before.
            * ``nonce``: The signed nonce, or ``None``. Applications must enforce replay detection.
            * ``body``: Content bytes before decoding, after validating their covered digest; ``None`` otherwise.

        :raises InvalidSignature: Signature, required coverage, or body-digest validation fails.
        :raises HTTPMessageSignaturesException: The algorithm, required components, body type, or selection policy is invalid.
        """
        if require_components is None:
            require_components = (
                ("@status", '"@method";req', '"@authority";req', '"@target-uri";req')
                if isinstance(message, requests.Response)
                else ("@method", "@authority", "@target-uri")
            )
        try:
            cls._validate_header_names(message)
        except RequestsHttpSignatureException as e:
            raise InvalidSignature(str(e)) from e
        if body is None:
            body = cls.get_body(message)

        verifier = cls.verifier_class(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=cls.component_resolver_class,
        )
        verify_results = verifier.verify(
            message,
            max_age=max_age,
            expect_tag=expect_tag,
            expect_label=expect_label,
            require_components=require_components,
            body=body,
        )
        if len(verify_results) != 1:
            raise InvalidSignature("Select a single signature using expect_tag and expect_label")
        return verify_results[0]

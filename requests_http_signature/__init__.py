import datetime
import email.utils
import hashlib
import secrets
from typing import List

import http_sfv
import requests

from requests.exceptions import RequestException
from http_message_signatures import (algorithms, HTTPSignatureComponentResolver, HTTPSignatureKeyResolver,  # noqa: F401
                                     HTTPMessageSigner, HTTPMessageVerifier, HTTPSignatureAlgorithm, InvalidSignature)
from http_message_signatures.structures import CaseInsensitiveDict


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
        A list of lowercased header names or derived component IDs ("@method", "@target-uri", "@authority",
        "@scheme", "@request-target", "@path", "@query", "@query-params", "@status", or "@request-response" as
        specified in the standard) to sign.
    :param label: The label to use to identify the signature.
    :param include_alg:
        By default, the signature parameters will include the ``alg`` parameter, using it to identify the signature
        algorithm. If you wish not to include this parameter, set this to ``False``.
    :param use_nonce:
        Set this to ``True`` to include a unique message-specific nonce in the signature parameters. The format of
        the nonce can be controlled by subclassing this class and overloading the ``get_nonce()`` method.
    :param expires_in:
        Use this to set the ``expires`` signature parameter to the time of signing plus the given timedelta.
    :param component_resolver_class:
        Use this to subclass ``http_message_signatures.HTTPSignatureComponentResolver`` and customize header and
        derived component retrieval if needed.
    """
    _digest_hashers = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}

    def __init__(self, *,
                 signature_algorithm: HTTPSignatureAlgorithm,
                 key: bytes = None,
                 key_id: str,
                 key_resolver: HTTPSignatureKeyResolver = None,
                 covered_component_ids: List[str] = ("@method", "@authority", "@target-uri"),
                 label: str = None,
                 include_alg: bool = True,
                 use_nonce: bool = False,
                 expires_in: datetime.timedelta = None,
                 component_resolver_class: type = HTTPSignatureComponentResolver):
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
        handler_args = dict(signature_algorithm=signature_algorithm,
                            key_resolver=key_resolver,
                            component_resolver_class=component_resolver_class)
        self.signer = HTTPMessageSigner(**handler_args)

    def add_date(self, request, timestamp):
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def add_digest(self, request, algorithm="sha-256"):
        if request.body is None and "content-digest" in self.covered_component_ids:
            raise RequestsHttpSignatureException("Could not compute digest header for request without a body")
        if request.body is not None and "Content-Digest" not in request.headers:
            if "content-digest" not in self.covered_component_ids:
                self.covered_component_ids = list(self.covered_component_ids) + ["content-digest"]
            hasher = self._digest_hashers[algorithm]
            digest = hasher(request.body).digest()
            digest_node = http_sfv.Dictionary({algorithm: digest})
            request.headers["Content-Digest"] = str(digest_node)

    def get_nonce(self, request):
        if self.use_nonce:
            return secrets.token_urlsafe(16)

    def get_created(self, request):
        created = datetime.datetime.now()
        self.add_date(request, timestamp=int(created.timestamp()))
        # TODO: add Date to covered components
        return created

    def get_expires(self, request, created):
        if self.expires_in:
            return datetime.datetime.now() + self.expires_in

    def __call__(self, request):
        self.add_digest(request)
        created = self.get_created(request)
        expires = self.get_expires(request, created=created)
        self.signer.sign(request,
                         key_id=self.key_id,
                         created=created,
                         expires=expires,
                         nonce=self.get_nonce(request),
                         label=self.label,
                         include_alg=self.include_alg,
                         covered_component_ids=self.covered_component_ids)
        return request

    @classmethod
    def verify(cls, request, *,
               signature_algorithm: HTTPSignatureAlgorithm,
               key_resolver: HTTPSignatureKeyResolver,
               component_resolver_class: type = HTTPSignatureComponentResolver):
        """
        Verify an HTTP message signature.

        :param signature_algorithm:
            One of ``requests_http_signature.algorithms.HMAC_SHA256``,
            ``requests_http_signature.algorithms.ECDSA_P256_SHA256``,
            ``requests_http_signature.algorithms.ED25519``,
            ``requests_http_signature.algorithms.RSA_PSS_SHA512``, or
            ``requests_http_signature.algorithms.RSA_V1_5_SHA256``.
        :param key_resolver:
            Instead of specifying a fixed key, you can instead pass a key resolver, which should be an instance of a
            subclass of ``http_message_signatures.HTTPSignatureKeyResolver``. A key resolver should have two methods,
            ``get_private_key(key_id)`` (required only for signing) and ``get_public_key(key_id)`` (required only for
            verifying). Your implementation should ensure that the key id is recognized and return the corresponding
            key material as PEM bytes (or shared secret bytes for HMAC).
        :param component_resolver_class:
            Use this to subclass ``http_message_signatures.HTTPSignatureComponentResolver`` and customize header and
            derived component retrieval if needed.
        """
        verifier = HTTPMessageVerifier(signature_algorithm=signature_algorithm,
                                       key_resolver=key_resolver,
                                       component_resolver_class=component_resolver_class)
        verify_result = verifier.verify(request)
        # TODO: get content-digest from verify result, not from independent parsing of headers
        # TODO: add options to require specific components
        headers = CaseInsensitiveDict(request.headers)
        if "content-digest" in headers:
            if request.body is None:
                raise InvalidSignature("Found a content-digest header in a request with no body")
            digest = http_sfv.Dictionary()
            digest.parse(headers["content-digest"].encode())
            for k, v in digest.items():
                if k not in cls._digest_hashers:
                    raise InvalidSignature(f'Unsupported digest algorithm "{k}"')
                raw_digest = v.value
                hasher = cls._digest_hashers[k]
                expect_digest = hasher(request.body).digest()
                if raw_digest != expect_digest:
                    raise InvalidSignature("The content-digest header does not match the request body")
        return verify_result

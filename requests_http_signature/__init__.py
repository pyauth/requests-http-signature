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
    hasher_name = "sha-256"
    hasher_constructor = hashlib.sha256

    def __init__(self, *,
                 key: bytes = None,
                 key_id: str,
                 label: str = None,
                 include_alg: bool = True,
                 use_nonce: bool = False,
                 covered_component_ids: List[str] = ("@method", "@authority", "@target-uri"),
                 expires_in: datetime.timedelta = None,
                 signature_algorithm: HTTPSignatureAlgorithm,
                 key_resolver: HTTPSignatureKeyResolver = None,
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

    def add_digest(self, request):
        if request.body is None and "content-digest" in self.covered_component_ids:
            raise RequestsHttpSignatureException("Could not compute digest header for request without a body")
        if request.body is not None and "Content-Digest" not in request.headers:
            if "content-digest" not in self.covered_component_ids:
                self.covered_component_ids = list(self.covered_component_ids) + ["content-digest"]
            digest = self.hasher_constructor(request.body).digest()
            digest_node = http_sfv.Dictionary({self.hasher_name: digest})
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
        verifier = HTTPMessageVerifier(signature_algorithm=signature_algorithm,
                                       key_resolver=key_resolver,
                                       component_resolver_class=component_resolver_class)
        verifier.verify(request)
        headers = CaseInsensitiveDict(request.headers)
        if "content-digest" in headers:
            if request.body is None:
                raise InvalidSignature("Found a content-digest header in a request with no body")
            digest = http_sfv.Dictionary()
            digest.parse(headers["content-digest"].encode())
            for k, v in digest.items():
                if k != cls.hasher_name:
                    raise InvalidSignature(f'Unsupported digest algorithm "{k}"')
                raw_digest = v.value
            expect_digest = cls.hasher_constructor(request.body).digest()
            if raw_digest != expect_digest:
                raise InvalidSignature("The content-digest header does not match the request body")

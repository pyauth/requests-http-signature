#!/usr/bin/env python

import base64
import io
import json
import logging
import os
import sys
import unittest

import http_sfv
import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http_message_signatures import HTTPMessageSigner  # noqa: E402
from http_message_signatures import InvalidSignature  # noqa: E402

from requests_http_signature import HTTPSignatureAuth, algorithms  # noqa: E402

logging.basicConfig(level="DEBUG")

default_keyid = "my_key_id"
hmac_secret = b"monorail_cat"
passphrase = b"passw0rd"


class TestAdapter(HTTPAdapter):
    def __init__(self, auth):
        super().__init__()
        self.client_auth = auth

    def send(self, request, *args, **kwargs):
        verify_args = dict(
            signature_algorithm=self.client_auth.signer.signature_algorithm,
            key_resolver=self.client_auth.signer.key_resolver,
        )
        HTTPSignatureAuth.verify(request, **verify_args)
        if request.body is not None:
            request.body = request.body[::-1]
            try:
                HTTPSignatureAuth.verify(request, **verify_args)
                raise Exception("Expected InvalidSignature to be raised")
            except InvalidSignature:
                pass
        response = requests.Response()
        response.request = request
        response.status_code = requests.codes.ok
        response.url = request.url
        response.headers["Received-Signature-Input"] = request.headers["Signature-Input"]
        response.headers["Received-Signature"] = request.headers["Signature"]
        response.raw = io.BytesIO(json.dumps({}).encode())
        signer = HTTPMessageSigner(
            signature_algorithm=self.client_auth.signer.signature_algorithm,
            key_resolver=self.client_auth.signer.key_resolver,
        )
        hasher = HTTPSignatureAuth._content_digest_hashers["sha-256"]
        digest = hasher(response.raw.getvalue()).digest()
        response.headers["Content-Digest"] = str(http_sfv.Dictionary({"sha-256": digest}))
        signer.sign(
            response,
            key_id=default_keyid,
            covered_component_ids=("@method", "@authority", "content-digest", "@target-uri"),
        )
        return response


class DigestlessSignatureAuth(HTTPSignatureAuth):
    def add_digest(self, request):
        pass


class TestRequestsHTTPSignature(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.auth = HTTPSignatureAuth(key_id=default_keyid, key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)
        self.session.mount("http://", TestAdapter(self.auth))
        self.session.mount("https://", TestAdapter(self.auth))

    def test_basic_statements(self):
        url = "http://example.com/path?query#fragment"
        self.session.get(url, auth=self.auth)
        self.auth.signer.key_resolver.resolve_public_key = lambda k: b"abc"
        with self.assertRaises(InvalidSignature):
            self.session.get(url, auth=self.auth)
        self.auth.signer.key_resolver.resolve_private_key = lambda k: b"abc"
        self.session.get(url, auth=self.auth)
        res = self.session.post(url, auth=self.auth, data=b"xyz")
        verify_args = dict(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.auth.signer.key_resolver)
        HTTPSignatureAuth.verify(res, **verify_args)
        res.headers["Content-Digest"] = res.headers["Content-Digest"][::-1]
        with self.assertRaises(InvalidSignature):
            HTTPSignatureAuth.verify(res, **verify_args)
        del res.headers["Content-Digest"]
        with self.assertRaises(InvalidSignature):
            HTTPSignatureAuth.verify(res, **verify_args)
        res.headers["Signature"] = res.headers["Signature"][::-1]
        with self.assertRaises(InvalidSignature):
            HTTPSignatureAuth.verify(res, **verify_args)
        del res.headers["Signature"]
        with self.assertRaises(InvalidSignature):
            HTTPSignatureAuth.verify(res, **verify_args)

    def test_auto_cover_authorization_header(self):
        url = "http://example.com/path?query#fragment"
        res = self.session.get(url, auth=self.auth, headers={"Authorization": "Bearer 12345"})
        self.assertIn('"authorization"', res.headers["Received-Signature-Input"])

    def test_b21(self):
        url = "https://example.com/foo?param=Value&Pet=dog"
        self.session.post(
            url,
            json={"hello": "world"},
            headers={
                "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
                "Content-Digest": (
                    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+"
                    "AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
                ),
            },
            auth=self.auth,
        )

    @unittest.skip("TODO")
    def test_rsa(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        url = "http://example.com/path?query#fragment"
        auth = HTTPSignatureAuth(algorithm="rsa-sha256", key=private_key_pem, key_id="sekret", passphrase=passphrase)
        self.session.get(url, auth=auth, headers=dict(pubkey=base64.b64encode(public_key_pem)))


if __name__ == "__main__":
    unittest.main()

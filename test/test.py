#!/usr/bin/env python

import os, sys, unittest, logging, base64

import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from requests_http_signature import algorithms, HTTPSignatureAuth  # noqa: E402
from http_message_signatures import InvalidSignature  # noqa: E402

logging.basicConfig(level="DEBUG")

default_keyid = "my_key_id"
hmac_secret = b"monorail_cat"
passphrase = b"passw0rd"


class TestAdapter(HTTPAdapter):
    def __init__(self, auth):
        super().__init__()
        self.client_auth = auth

    def send(self, request, *args, **kwargs):
        verify_args = dict(signature_algorithm=self.client_auth.signer.signature_algorithm,
                           key_resolver=self.client_auth.signer.key_resolver)
        HTTPSignatureAuth.verify(request, **verify_args)
        if request.body is not None:
            request.body = request.body[::-1]
            try:
                HTTPSignatureAuth.verify(request, **verify_args)
                raise Exception("Expected InvalidSignature to be raised")
            except InvalidSignature:
                pass
        response = requests.Response()
        response.status_code = requests.codes.ok
        response.url = request.url
        return response


class DigestlessSignatureAuth(HTTPSignatureAuth):
    def add_digest(self, request):
        pass


class TestRequestsHTTPSignature(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.auth = HTTPSignatureAuth(key_id=default_keyid, key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)
        self.session.mount("http://", TestAdapter(self.auth))

    def test_basic_statements(self):
        url = 'http://example.com/path?query#fragment'
        self.session.get(url, auth=self.auth)
        self.auth.signer.key_resolver.resolve_public_key = lambda k: b"abc"
        with self.assertRaises(InvalidSignature):
            self.session.get(url, auth=self.auth)
        self.auth.signer.key_resolver.resolve_private_key = lambda k: b"abc"
        self.session.get(url, auth=self.auth)
        self.session.post(url, auth=self.auth, data=b"xyz")

    def test_expired_signature(self):
        "TODO"

    @unittest.skip("TODO")
    def test_rsa(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        )
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        url = 'http://example.com/path?query#fragment'
        auth = HTTPSignatureAuth(algorithm="rsa-sha256", key=private_key_pem, key_id="sekret", passphrase=passphrase)
        self.session.get(url, auth=auth, headers=dict(pubkey=base64.b64encode(public_key_pem)))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, unittest, json, logging, base64

import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) # noqa

from requests_http_signature import HTTPSignatureAuth

hmac_secret = b"monorail_cat"
passphrase = b"passw0rd"

class TestAdapter(HTTPAdapter):
    def send(self, request, *args, **kwargs):
        def key_resolver(key_id, algorithm):
            if "pubkey" in request.headers:
                return base64.b64decode(request.headers["pubkey"])
            return hmac_secret
        HTTPSignatureAuth(key=hmac_secret).verify(request, key_resolver=key_resolver)
        response = requests.Response()
        response.status_code = requests.codes.ok
        response.url = request.url
        return response

class TestRequestsHTTPSignature(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level="DEBUG")
        self.session = requests.Session()
        self.session.mount("http://", TestAdapter())

    def test_basic_statements(self):
        url = 'http://example.com/path?query#fragment'
        self.session.get(url, auth=HTTPSignatureAuth(key=hmac_secret))
        with self.assertRaises(AssertionError):
            self.session.get(url, auth=HTTPSignatureAuth(key=hmac_secret[::-1]))

    def test_rfc_example(self):
        url = 'http://example.org/foo'
        payload = {"hello": "world"}
        date = "Tue, 07 Jun 2014 20:51:35 GMT"
        auth = HTTPSignatureAuth(key=hmac_secret,
                                 headers=["(request-target)", "host", "date", "digest", "content-length"])
        self.session.post(url, json=payload, headers={"Date": date}, auth=auth)

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
        auth = HTTPSignatureAuth(algorithm="rsa-sha256", key=private_key_pem, passphrase=passphrase)
        self.session.get(url, auth=auth, headers=dict(pubkey=base64.b64encode(public_key_pem)))

if __name__ == '__main__':
    unittest.main()

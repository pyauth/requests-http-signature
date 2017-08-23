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
    def __init__(self, testcase):
        self.testcase = testcase
    def send(self, request, *args, **kwargs):
        def key_resolver(key_id, algorithm):
            if "pubkey" in request.headers:
                return base64.b64decode(request.headers["pubkey"])
            return hmac_secret
        HTTPSignatureAuth.verify(request, key_resolver=key_resolver)
        if "expectSig" in request.headers:
            self.testcase.assertEqual(request.headers["expectSig"],
                                      HTTPSignatureAuth.get_sig_struct(request)["signature"])
        response = requests.Response()
        response.status_code = requests.codes.ok
        response.url = request.url
        return response

class DigestlessSignatureAuth(HTTPSignatureAuth):
    def add_digest(self, request):
        pass

class TestRequestsHTTPSignature(unittest.TestCase):
    def setUp(self):
        logging.basicConfig(level="DEBUG")
        self.session = requests.Session()
        self.session.mount("http://", TestAdapter(self))

    def test_basic_statements(self):
        url = 'http://example.com/path?query#fragment'
        self.session.get(url, auth=HTTPSignatureAuth(key=hmac_secret, key_id="sekret"))
        with self.assertRaises(AssertionError):
            self.session.get(url, auth=HTTPSignatureAuth(key=hmac_secret[::-1], key_id="sekret"))

    def test_rfc_examples(self):
        # The date in the RFC is wrong (2014 instead of 2012).
        # See https://github.com/joyent/node-http-signature/issues/54
        # Also, the values in https://github.com/joyent/node-http-signature/blob/master/test/verify.test.js don't match
        # up with ours. This is because node-http-signature seems to compute the content-length incorrectly in its test
        # suite (it should be 18, but they use 17).
        url = 'http://example.org/foo'
        payload = {"hello": "world"}
        date = "Thu, 05 Jan 2012 21:31:40 GMT"
        auth = HTTPSignatureAuth(key=hmac_secret,
                                 key_id="sekret",
                                 headers=["(request-target)", "host", "date", "digest", "content-length"])
        self.session.post(url, json=payload, headers={"Date": date}, auth=auth)

        pubkey_fn = os.path.join(os.path.dirname(__file__), "pubkey.pem")
        privkey_fn = os.path.join(os.path.dirname(__file__), "privkey.pem")
        url = "http://example.com/foo?param=value&pet=dog"

        with open(pubkey_fn, "rb") as pubkey, open(privkey_fn, "rb") as privkey:
            pubkey_b64 = base64.b64encode(pubkey.read())
            auth = DigestlessSignatureAuth(algorithm="rsa-sha256", key=privkey.read(), key_id="Test")
            expect_sig = "ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=" # noqa
            headers = {"Date": date, "pubkey": pubkey_b64, "expectSig": expect_sig}
            self.session.post(url, json=payload, headers=headers, auth=auth)

        with open(pubkey_fn, "rb") as pubkey, open(privkey_fn, "rb") as privkey:
            pubkey_b64 = base64.b64encode(pubkey.read())
            auth = HTTPSignatureAuth(algorithm="rsa-sha256", key=privkey.read(), key_id="Test",
                                     headers="(request-target) host date content-type digest content-length".split())
            expect_sig = "DkOOyDlO9rXmOiU+k6L86N4UFEcey2YD+/Bz8c+Sr6XVDtDCxUuFEHMO+Atag/V1iLu+3KczVrCwjaZ39Ox3RufJghHzhTffyEkfPI6Ivf271mfRU9+wLxuGj9f+ATVO14nvcZyQjAMLvV7qh35zQcYdeD5XyxLLjuYUnK14rYI=" # noqa
            headers = {"Date": date, "pubkey": pubkey_b64, "expectSig": expect_sig, "content-type": "application/json"}
            self.session.post(url, json=payload, headers=headers, auth=auth)

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

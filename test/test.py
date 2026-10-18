#!/usr/bin/env python

import base64
import io
import json
import logging
import os
import sys
import unittest

import http_sf.compat as http_sfv
import requests
from requests.adapters import HTTPAdapter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http_message_signatures import HTTPMessageSigner, InvalidSignature

from requests_http_signature import HTTPSignatureAuth, RequestsHttpSignatureException, algorithms

logging.basicConfig(level="DEBUG")

default_keyid = "my_key_id"
hmac_secret = b"monorail_cat"
passphrase = b"passw0rd"


class TestAdapter(HTTPAdapter):
    def __init__(self, auth):
        super().__init__()
        self.client_auth = auth

    def send(self, request, *args, **kwargs):
        verify_args = {
            "signature_algorithm": self.client_auth.signer.signature_algorithm,
            "key_resolver": self.client_auth.signer.key_resolver,
        }
        HTTPSignatureAuth.verify(request, **verify_args)
        if request.body is not None:
            request.body = request.body[::-1]
            try:
                HTTPSignatureAuth.verify(request, **verify_args)
                raise AssertionError("Expected InvalidSignature to be raised")
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
            covered_component_ids=(
                "@status",
                '"@method";req',
                '"@authority";req',
                "content-digest",
                '"@target-uri";req',
            ),
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
        verify_args = {"signature_algorithm": algorithms.HMAC_SHA256, "key_resolver": self.auth.signer.key_resolver}
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

    def verify(self, message, **kwargs):
        return HTTPSignatureAuth.verify(
            message,
            signature_algorithm=algorithms.HMAC_SHA256,
            key_resolver=self.auth.signer.key_resolver,
            **kwargs,
        )

    def test_response_defaults_cover_status_and_request(self):
        response = self.session.get("https://example.com/", auth=self.auth)
        result = self.verify(response)
        self.assertEqual(result.covered_components['"@status"'], "200")
        self.assertEqual(result.covered_components['"@method";req'], "GET")
        response.status_code = 403
        with self.assertRaises(InvalidSignature):
            self.verify(response)

    def test_case_sensitive_query_components(self):
        components = ('"@query-param";name="Foo"', '"@query-param";name="foo"')
        self.auth.covered_component_ids = components
        request = requests.Request("GET", "https://example.com/?Foo=upper&foo=lower", auth=self.auth).prepare()
        result = self.verify(request, require_components=components)
        self.assertEqual(result.covered_components[components[0]], "upper")
        self.assertEqual(result.covered_components[components[1]], "lower")

    def test_component_parameter_order_and_duplicates(self):
        first = '"example-dict";key="a";sf'
        second = '"example-dict";sf;key="a"'
        self.auth.covered_component_ids = (first,)
        request = requests.Request(
            "GET", "https://example.com/", headers={"Example-Dict": "a=1"}, auth=self.auth
        ).prepare()
        self.assertIn(first, self.verify(request, require_components=(second,)).covered_components)
        for components in ((first, second), ("date", '"date"'), "@method"):
            self.auth.covered_component_ids = components
            with self.assertRaises(RequestsHttpSignatureException):
                self.auth(request)

    def test_case_insensitive_header_collisions_are_rejected(self):
        request = requests.Request("GET", "https://example.com/", auth=self.auth).prepare()
        request.headers = dict(request.headers)
        request.headers["date"] = request.headers["Date"]
        with self.assertRaises(RequestsHttpSignatureException):
            self.auth(request)
        with self.assertRaises(InvalidSignature):
            self.verify(request)

    def test_b21(self):
        url = "https://example.com/foo?param=Value&Pet=dog"
        self.session.post(
            url,
            json={"hello": "world"},
            headers={
                "Date": "Tue, 20 Apr 2021 02:07:55 GMT",
                "Content-Digest": (
                    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
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
        self.session.get(url, auth=auth, headers={"pubkey": base64.b64encode(public_key_pem)})


if __name__ == "__main__":
    unittest.main()

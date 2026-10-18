#!/usr/bin/env python

import base64
import gzip
import hashlib
import io
import json
import logging
import os
import sys
import unittest

import http_sf.compat as http_sfv
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

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

    def test_text_form_json_and_multipart_bodies(self):
        cases = [
            {"data": "caf\u00e9"},
            {"data": {"name": "caf\u00e9"}},
            {"json": {"name": "caf\u00e9"}},
            {"files": {"file": ("name.txt", b"hello")}},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                request = requests.Request("POST", "https://example.com/", auth=self.auth, **kwargs).prepare()
                self.assertIsInstance(request.body, bytes)
                self.assertEqual(int(request.headers["Content-Length"]), len(request.body))
                self.assertEqual(self.verify(request).body, request.body)

    def test_streams_require_supplied_digests_and_are_not_consumed(self):
        for body in (io.BytesIO(b"hello"), iter([b"hello"])):
            with self.assertRaisesRegex(RequestsHttpSignatureException, "precomputed Content-Digest"):
                requests.Request("POST", "https://example.com/", data=body, auth=self.auth).prepare()
        stream = io.BytesIO(b"prefixhello")
        stream.seek(6)
        digest = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(b"hello").digest()}))
        request = requests.Request(
            "POST", "https://example.com/", data=stream, headers={"Content-Digest": digest}, auth=self.auth
        ).prepare()
        self.assertEqual(stream.tell(), 6)
        with self.assertRaisesRegex(InvalidSignature, "streaming request requires body="):
            self.verify(request)
        self.assertEqual(self.verify(request, body=b"hello").body, b"hello")
        self.assertEqual(stream.tell(), 6)
        with self.assertRaises(InvalidSignature):
            self.verify(request, body=b"changed")

    def test_empty_response_and_explicit_empty_digest(self):
        response = requests.Response()
        response.request = requests.Request("GET", "https://example.com/").prepare()
        response.url = response.request.url
        response.status_code = 204
        response._content = b""
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=("@status",))
        self.assertIsNone(self.verify(response, require_components=("@status",)).body)
        self.auth.covered_component_ids = ("content-digest",)
        request = requests.Request("GET", "https://example.com/", auth=self.auth).prepare()
        self.assertEqual(self.verify(request, require_components=("content-digest",)).body, b"")

    def test_compressed_response_uses_encoded_bytes(self):
        encoded = gzip.compress(b"hello")
        response = requests.Response()
        response.request = requests.Request("GET", "https://example.com/").prepare()
        response.url = response.request.url
        response.status_code = 200
        response.headers.update(
            {
                "Content-Encoding": "gzip",
                "Content-Digest": str(http_sfv.Dictionary({"sha-256": hashlib.sha256(encoded).digest()})),
            }
        )
        response.raw = HTTPResponse(
            body=io.BytesIO(encoded), headers=response.headers, preload_content=False, decode_content=False
        )
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=("@status", "content-digest"))
        with self.assertRaisesRegex(InvalidSignature, "Encoded responses require body="):
            self.verify(response, require_components=("@status",))
        raw_body = response.raw.read(decode_content=False)
        result = self.verify(response, require_components=("@status",), body=raw_body)
        self.assertEqual(gzip.decompress(result.body), b"hello")
        with self.assertRaises(InvalidSignature):
            self.verify(response, require_components=("@status",), body=b"hello")

    def test_invalid_digest_fields_raise_invalid_signature(self):
        digest = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(b"hello").digest()}))
        for value in ("bad : syntax", "sha-256=(1 2)", "sha-256=1", "", digest + ", " + digest, "unknown=:aGVsbG8=:"):
            with self.subTest(value=value):
                request = requests.Request(
                    "POST", "https://example.com/", data=b"hello", headers={"Content-Digest": value}
                ).prepare()
                self.auth.signer.sign(request, key_id=default_keyid, covered_component_ids=("content-digest",))
                with self.assertRaises(InvalidSignature):
                    self.verify(request, require_components=())

    def test_selected_digest_member_is_sufficient(self):
        component = '"content-digest";key="sha-256";sf'
        self.auth.covered_component_ids = (component,)
        request = requests.Request("POST", "https://example.com/", data=b"hello", auth=self.auth).prepare()
        result = self.verify(request, require_components=('"content-digest";sf;key="sha-256"',))
        self.assertNotIn('"content-digest"', result.covered_components)
        self.assertEqual(result.body, b"hello")

    def test_stale_supplied_digest_is_rejected_before_signing(self):
        with self.assertRaisesRegex(RequestsHttpSignatureException, "does not match"):
            requests.Request(
                "POST",
                "https://example.com/",
                data=b"hello",
                auth=self.auth,
                headers={"Content-Digest": str(http_sfv.Dictionary({"sha-256": hashlib.sha256(b"stale").digest()}))},
            ).prepare()

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

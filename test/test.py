#!/usr/bin/env python

import base64
import datetime
import gzip
import hashlib
import io
import json
import logging
import os
import sys
import unittest
from unittest import mock
from urllib.parse import urljoin, urlsplit

import http_sf.compat as http_sfv
import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPHeaderDict
from urllib3.response import HTTPResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http_message_signatures import HTTPMessageSigner, HTTPMessageVerifier, InvalidSignature
from http_message_signatures.exceptions import HTTPMessageSignaturesException

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

    def test_header_matching_preserves_case_insensitivity(self):
        request = requests.Request("POST", "https://example.com/", data=b"hello", auth=self.auth).prepare()
        request.headers = {name.lower(): value for name, value in request.headers.items()}
        self.assertEqual(self.verify(request).body, b"hello")
        self.auth(request)
        self.assertEqual(self.verify(request).body, b"hello")

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

    def test_external_signing_prepares_and_applies_without_a_local_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        auth = HTTPSignatureAuth(
            key_id="remote",
            signature_algorithm=algorithms.ED25519,
            tag="app",
            use_nonce=True,
            expires_in=datetime.timedelta(minutes=5),
        )
        with self.assertRaisesRegex(RequestsHttpSignatureException, r"prepare\(\)/apply\(\)"):
            requests.Request("POST", "https://example.com/", data="hello", auth=auth).prepare()
        request = self.session.prepare_request(requests.Request("POST", "https://example.com/", data="hello"))
        prepared = auth.prepare(request)
        self.assertNotIn("Signature", request.headers)
        self.assertIn(b'"content-digest":', prepared.signature_base)
        self.assertIn(b'"date":', prepared.signature_base)
        self.assertIs(auth.apply(request, prepared, key.sign(prepared.signature_base)), request)

        class Resolver:
            def resolve_public_key(self, key_id):
                return key.public_key()

        result = HTTPSignatureAuth.verify(
            request, signature_algorithm=algorithms.ED25519, key_resolver=Resolver(), expect_tag="app"
        )
        self.assertEqual(result.body, b"hello")
        self.assertIsInstance(result.nonce, str)
        self.assertEqual(result.parameters["expires"] - result.parameters["created"], 300)

    def test_external_signing_rejects_changed_body_or_headers(self):
        for change in ("body", "header"):
            with self.subTest(change=change):
                request = requests.Request("POST", "https://example.com/", data=b"hello").prepare()
                prepared = self.auth.prepare(request)
                signature = algorithms.HMAC_SHA256(shared_secret=hmac_secret).sign(prepared.signature_base)
                if change == "body":
                    request.body = b"changed"
                else:
                    request.headers["Date"] = "different"
                headers = dict(request.headers)
                with self.assertRaises((RequestsHttpSignatureException, HTTPMessageSignaturesException)):
                    self.auth.apply(request, prepared, signature)
                self.assertEqual(dict(request.headers), headers)

    def test_interleaved_external_signatures_and_append(self):
        first = requests.Request("POST", "https://example.com/first", data=b"first").prepare()
        second = requests.Request("POST", "https://example.com/second", data=b"second").prepare()
        prepared_first = self.auth.prepare(first)
        prepared_second = self.auth.prepare(second)
        algorithm = algorithms.HMAC_SHA256(shared_secret=hmac_secret)
        self.auth.apply(second, prepared_second, algorithm.sign(prepared_second.signature_base))
        self.auth.apply(first, prepared_first, algorithm.sign(prepared_first.signature_base))
        self.assertEqual(self.verify(first).body, b"first")
        self.assertEqual(self.verify(second).body, b"second")
        self.auth.label, self.auth.tag = "second", "app"
        prepared = self.auth.prepare(first)
        self.auth.apply(first, prepared, algorithm.sign(prepared.signature_base), append_if_signature_exists=True)
        self.assertEqual(self.verify(first, expect_tag="app").label, "second")

    def test_signature_selection(self):
        request = requests.Request("GET", "https://example.com/").prepare()
        self.auth.label, self.auth.tag = "first", "app"
        self.auth(request)
        self.auth.label, self.auth.tag = "second", "other"
        self.auth.append_if_signature_exists = True
        self.auth(request)
        with self.assertRaises(InvalidSignature):
            self.verify(request)
        self.assertEqual(self.verify(request, expect_tag="app", expect_label="first").label, "first")
        with self.assertRaises(HTTPMessageSignaturesException):
            self.verify(request, expect_label="first")
        with self.assertRaises(InvalidSignature):
            self.verify(request, expect_tag="missing")
        self.auth.label, self.auth.tag = "third", "app"
        self.auth(request)
        with self.assertRaisesRegex(InvalidSignature, "Select a single signature"):
            self.verify(request, expect_tag="app")

    def test_verifier_age_and_clock_skew_policy(self):
        request = requests.Request("GET", "https://example.com/").prepare()
        self.auth.signer.sign(
            request, key_id=default_keyid, created=datetime.datetime.now() - datetime.timedelta(days=2)
        )
        with self.assertRaises(InvalidSignature):
            self.verify(request)
        self.verify(request, max_age=None)

        class TolerantVerifier(HTTPMessageVerifier):
            max_clock_skew = datetime.timedelta(minutes=1)

        class TolerantAuth(HTTPSignatureAuth):
            verifier_class = TolerantVerifier

        self.auth.signer.sign(
            request, key_id=default_keyid, created=datetime.datetime.now() + datetime.timedelta(seconds=30)
        )
        with self.assertRaises(InvalidSignature):
            self.verify(request)
        TolerantAuth.verify(
            request, signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.auth.signer.key_resolver
        )

    def test_optional_creation_timestamp(self):
        request = requests.Request("GET", "https://example.com/").prepare()
        params = '("@method");keyid="my_key_id";alg="hmac-sha256"'
        base = f'"@method": GET\n"@signature-params": {params}'.encode()
        request.headers["Signature-Input"] = "sig=" + params
        request.headers["Signature"] = str(
            http_sfv.Dictionary({"sig": algorithms.HMAC_SHA256(shared_secret=hmac_secret).sign(base)})
        )
        with self.assertRaises(InvalidSignature):
            self.verify(request, require_components=("@method",), max_age=None)

        class OptionalCreatedVerifier(HTTPMessageVerifier):
            require_created = False

        class OptionalCreatedAuth(HTTPSignatureAuth):
            verifier_class = OptionalCreatedVerifier

        result = OptionalCreatedAuth.verify(
            request,
            require_components=("@method",),
            max_age=None,
            signature_algorithm=algorithms.HMAC_SHA256,
            key_resolver=self.auth.signer.key_resolver,
        )
        self.assertEqual(result.label, "sig")

    def test_explicit_redirect_workflow_signs_each_destination(self):
        verify = self.verify

        class RedirectAdapter(HTTPAdapter):
            def __init__(self, destination):
                super().__init__()
                self.destination = destination
                self.requests = []

            def send(self, request, **kwargs):
                verify(request)
                self.requests.append(request)
                response = requests.Response()
                response.request = request
                response.url = request.url
                response._content = b""
                response.status_code = 302 if len(self.requests) == 1 else 200
                if response.status_code == 302:
                    response.headers["Location"] = self.destination
                return response

        for location in ("/second", "https://other.example/second"):
            with self.subTest(location=location):
                adapter = RedirectAdapter(location)
                self.session.mount("https://", adapter)
                url = "https://example.com/first"
                response = self.session.get(url, auth=self.auth, allow_redirects=False)
                self.assertEqual(len(adapter.requests), 1)
                destination = urljoin(response.url, response.headers["Location"])
                origin, target = urlsplit(url), urlsplit(destination)
                response.close()
                if (origin.scheme, origin.netloc) != (target.scheme, target.netloc):
                    continue
                response = self.session.get(destination, auth=self.auth, allow_redirects=False)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(adapter.requests), 2)
                self.assertNotEqual(adapter.requests[0].headers["Signature"], adapter.requests[1].headers["Signature"])

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


class TestBinaryWrapping(unittest.TestCase):
    def setUp(self):
        self.auth = HTTPSignatureAuth(key_id=default_keyid, key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)

    def verify(self, message, components=(), **kwargs):
        return HTTPSignatureAuth.verify(
            message,
            require_components=components,
            signature_algorithm=algorithms.HMAC_SHA256,
            key_resolver=self.auth.signer.key_resolver,
            **kwargs,
        )

    def request(self, fields):
        request = requests.Request("GET", "https://example.com/").prepare()
        request.headers = HTTPHeaderDict(fields)
        return request

    def response(self, cookies):
        response = requests.Response()
        response.status_code = 200
        response.request = self.request([])
        response.headers = HTTPHeaderDict(("Set-Cookie", value) for value in cookies)
        return response

    def test_rfc_binary_wrapping_vectors_preserve_field_boundaries(self):
        self.auth.covered_component_ids = ('"example-header";bs',)
        request = self.request([("Example-Header", "value, with, lots"), ("Example-Header", "of, commas")])
        self.auth(request)
        result = self.verify(request, self.auth.covered_component_ids)
        self.assertEqual(
            result.covered_components['"example-header";bs'], ":dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:"
        )
        self.assertEqual(request.headers.getlist("Example-Header"), ["value, with, lots", "of, commas"])
        request.headers["Example-Header"] = "value, with, lots, of, commas"
        with self.assertRaises(InvalidSignature):
            self.verify(request, self.auth.covered_component_ids)
        self.auth(request)
        result = self.verify(request, self.auth.covered_component_ids)
        self.assertEqual(result.covered_components['"example-header";bs'], ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:")

    def test_binary_wrapping_normalizes_ows_folding_and_latin1_octets(self):
        self.auth.covered_component_ids = ('"example-header";bs',)
        request = self.request(
            [("Example-Header", " \tfirst\t\r\n second \t"), ("Example-Header", "\xff"), ("Example-Header", "")]
        )
        self.auth(request)
        result = self.verify(request, self.auth.covered_component_ids)
        self.assertEqual(result.covered_components['"example-header";bs'], ":Zmlyc3Qgc2Vjb25k:, :/w==:, ::")

    def test_incompatible_binary_wrapping_parameters_are_rejected(self):
        for component in (
            '"example-header";bs=?0',
            '"example-header";bs=1',
            '"example-header";bs;sf',
            '"example-header";bs;key="a"',
            '"example-header";bs;tr',
            '"@method";bs',
        ):
            with self.subTest(component=component):
                self.auth.covered_component_ids = (component,)
                with self.assertRaises(HTTPMessageSignaturesException):
                    self.auth(self.request([("Example-Header", "a=1")]))

    def test_binary_wrapping_does_not_hide_invalid_field_values(self):
        self.auth.covered_component_ids = ('"example-header";bs',)
        for value in ("one\ntwo", "one\r\ntwo", "one\x00two", "\u20ac"):
            with self.subTest(value=value), self.assertRaises(HTTPMessageSignaturesException):
                self.auth(self.request([("Example-Header", value)]))

    def test_multiple_set_cookie_is_automatically_covered_and_armored(self):
        cookies = ["a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT", "b=2; HttpOnly"]
        for components in ((), ("set-cookie",), ('"set-cookie";bs',)):
            with self.subTest(components=components):
                self.auth.covered_component_ids = components
                request = self.request([("Set-Cookie", cookies[0]), ("set-cookie", cookies[1])])
                self.auth(request)
                result = self.verify(request)
                self.assertIn('"set-cookie";bs', result.covered_components)
                self.assertNotIn('"set-cookie"', result.covered_components)
                self.assertEqual(request.headers.getlist("Set-Cookie"), cookies)
                request.headers["Set-Cookie"] = ", ".join(cookies)
                with self.assertRaises(InvalidSignature):
                    self.verify(request)

    def test_response_signer_and_requests_raw_header_recovery(self):
        from requests_http_signature import HTTPMessageSigner as RequestsSigner

        response = self.response(["a=1", "b=2"])
        signer = RequestsSigner(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.auth.signer.key_resolver)
        signer.sign(response, key_id=default_keyid, covered_component_ids=("@status", "set-cookie"))
        raw = HTTPResponse(body=io.BytesIO(b""), headers=response.headers, status=200, preload_content=False)
        received = HTTPAdapter().build_response(response.request, raw)
        self.assertEqual(received.headers["Set-Cookie"], "a=1, b=2")
        result = self.verify(received, ("@status",), body=b"")
        self.assertEqual(result.covered_components['"set-cookie";bs'], ":YT0x:, :Yj0y:")
        received.headers["Set-Cookie"] = "a=3, b=2"
        with self.assertRaisesRegex(InvalidSignature, "raw field lines"):
            self.verify(received, ("@status",), body=b"")

    def test_unsigned_and_unarmored_multiple_cookies_are_rejected(self):
        legacy = HTTPMessageSigner(
            signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.auth.signer.key_resolver
        )
        for components in (("@status",), ("@status", "set-cookie")):
            with self.subTest(components=components):
                response = self.response(["a=1", "b=2"])
                legacy.sign(response, key_id=default_keyid, covered_component_ids=components)
                with self.assertRaises(InvalidSignature):
                    self.verify(response, ("@status",), body=b"")
                raw = HTTPResponse(body=io.BytesIO(b""), headers=response.headers, status=200, preload_content=False)
                received = HTTPAdapter().build_response(response.request, raw)
                with self.assertRaises(InvalidSignature):
                    self.verify(received, ("@status",), body=b"")

    def test_single_cookie_can_use_plain_or_binary_coverage(self):
        for component in ("set-cookie", '"set-cookie";bs'):
            with self.subTest(component=component):
                response = self.response(["a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT"])
                self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=("@status", component))
                self.verify(response, ("@status", component), body=b"")

    def test_binary_wrapping_can_target_associated_request(self):
        response = self.response([])
        response.request = self.request([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        components = ("@status", '"set-cookie";req;bs')
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=components)
        result = self.verify(response, components, body=b"")
        self.assertEqual(result.covered_components['"set-cookie";req;bs'], ":YT0x:, :Yj0y:")

    def test_binary_wrapped_content_digest_is_verified(self):
        self.auth.covered_component_ids = ('"content-digest";bs',)
        request = requests.Request("POST", "https://example.com/", data=b"hello", auth=self.auth).prepare()
        self.assertEqual(self.verify(request, self.auth.covered_component_ids).body, b"hello")
        request.body = b"wrong"
        with self.assertRaises(InvalidSignature):
            self.verify(request, self.auth.covered_component_ids)

    def test_external_signing_rejects_cookie_boundary_changes(self):
        request = self.request([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        prepared = self.auth.prepare(request)
        signature = algorithms.HMAC_SHA256(private_key=hmac_secret).sign(prepared.signature_base)
        request.headers["Set-Cookie"] = "a=1, b=2"
        with self.assertRaises(HTTPMessageSignaturesException):
            self.auth.apply(request, prepared, signature)


class TestVerificationWorkLimits(unittest.TestCase):
    def setUp(self):
        self.auth = HTTPSignatureAuth(key_id=default_keyid, key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)

    def verify(self, message, auth_class=HTTPSignatureAuth, **kwargs):
        return auth_class.verify(
            message, signature_algorithm=algorithms.HMAC_SHA256, key_resolver=self.auth.signer.key_resolver, **kwargs
        )

    def request(self):
        return requests.Request("GET", "https://example.com/", auth=self.auth).prepare()

    def response(self):
        response = requests.Response()
        response.status_code = 200
        response.request = self.request()
        response.raw = mock.Mock()
        response.raw.stream.side_effect = AssertionError("Response body must not be read")
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=("@status",))
        return response

    def test_size_limits_run_before_structured_field_parsing_and_key_resolution(self):
        cases = [
            ("headers", lambda r: r.headers.update({"X-Large": "a" * 65536})),
            ("count", lambda r: r.headers.update({f"X-{i}": "a" for i in range(101)})),
            ("signature", lambda r: r.headers.update({"Signature": "a" * 16385})),
            ("input", lambda r: r.headers.update({"Signature-Input": "a" * 16385})),
            ("url", lambda r: setattr(r, "url", "https://example.com/" + "a" * 8192)),
        ]
        for label, change in cases:
            with self.subTest(case=label):
                request = self.request()
                change(request)
                with (
                    mock.patch.object(HTTPMessageVerifier, "_parse_dict_header") as parse,
                    mock.patch.object(self.auth.signer.key_resolver, "resolve_public_key") as resolve,
                    self.assertRaisesRegex(InvalidSignature, "limit"),
                ):
                    self.verify(request)
                parse.assert_not_called()
                resolve.assert_not_called()

    def test_limits_include_raw_response_fields_and_associated_request(self):
        response = self.response()
        raw_headers = HTTPHeaderDict(response.headers)
        for i in range(101):
            raw_headers.add("Set-Cookie", f"cookie{i}=1")
        response.raw = HTTPResponse(body=io.BytesIO(b""), headers=raw_headers, status=200, preload_content=False)
        response.headers = requests.structures.CaseInsensitiveDict(raw_headers)
        with self.assertRaisesRegex(InvalidSignature, "limit"):
            self.verify(response, require_components=("@status",), body=b"")
        response = self.response()
        response.request.url += "a" * 8192
        with self.assertRaisesRegex(InvalidSignature, "limit"):
            self.verify(response, require_components=("@status",), body=b"")

    def test_split_signature_fields_share_one_size_budget(self):
        request = self.request()
        request.headers["Signature-Input"] = "a" * 9000
        request.headers.add("Signature-Input", "b" * 9000)
        with (
            mock.patch.object(HTTPMessageVerifier, "_parse_dict_header") as parse,
            self.assertRaisesRegex(InvalidSignature, "Signature field"),
        ):
            self.verify(request)
        parse.assert_not_called()

    def test_size_budgets_accept_the_boundary_and_reject_one_less(self):
        request = self.request()
        limits = {
            "verification_max_header_bytes": sum(len(k) + len(v) + 4 for k, v in request.headers.items()),
            "verification_max_header_count": len(request.headers),
            "verification_max_signature_field_bytes": max(
                len(request.headers["Signature"]), len(request.headers["Signature-Input"])
            ),
            "verification_max_url_length": len(request.url),
        }
        fits = type("Fits", (HTTPSignatureAuth,), limits)
        self.verify(request, auth_class=fits)
        for name, value in limits.items():
            too_small = type("TooSmall", (fits,), {name: value - 1})
            with self.subTest(limit=name), self.assertRaisesRegex(InvalidSignature, "limit"):
                self.verify(request, auth_class=too_small)

    def test_verification_limits_can_be_increased_for_application_profiles(self):
        class LargeHeaders(HTTPSignatureAuth):
            verification_max_header_bytes = 128 * 1024

        self.auth.covered_component_ids = ("x-large",)
        request = requests.Request(
            "GET", "https://example.com/", headers={"X-Large": "a" * 70000}, auth=self.auth
        ).prepare()
        with self.assertRaisesRegex(InvalidSignature, "limit"):
            self.verify(request, require_components=("x-large",))
        self.verify(request, auth_class=LargeHeaders, require_components=("x-large",))

    def test_invalid_signatures_and_missing_coverage_do_not_read_response(self):
        for change in ("missing", "malformed", "bad-signature", "missing-coverage", "unsigned-digest"):
            with self.subTest(change=change):
                response = self.response()
                requirements = ("@status",)
                if change == "missing":
                    del response.headers["Signature-Input"]
                elif change == "malformed":
                    response.headers["Signature-Input"] = 'sig=("unclosed'
                elif change == "bad-signature":
                    response.headers["Signature"] = str(http_sfv.Dictionary({"pyhms": b"x" * 32}))
                elif change == "missing-coverage":
                    requirements = ("@status", '"@method";req')
                else:
                    response.headers["Content-Digest"] = "sha-256=:AA==:"
                with self.assertRaises(InvalidSignature):
                    self.verify(response, require_components=requirements)
                response.raw.stream.assert_not_called()

    def test_ambiguous_selection_is_rejected_before_key_resolution(self):
        request = self.request()
        self.auth.signer.sign(request, key_id=default_keyid, tag="same", label="first")
        self.auth.signer.sign(
            request, key_id=default_keyid, tag="same", label="second", append_if_signature_exists=True
        )
        with (
            mock.patch.object(self.auth.signer.key_resolver, "resolve_public_key") as resolve,
            self.assertRaisesRegex(InvalidSignature, "single signature"),
        ):
            self.verify(request, expect_tag="same")
        resolve.assert_not_called()
        self.verify(request, expect_tag="same", expect_label="first")

    def test_dictionary_and_query_parsing_is_cached_for_one_verification(self):
        from requests_http_signature import resolvers

        self.auth.covered_component_ids = (
            '"example-dict";key="a"',
            '"example-dict";key="b"',
            '"@query-param";name="a"',
            '"@query-param";name="b"',
        )
        request = requests.Request(
            "GET", "https://example.com/?a=one&b=two", headers={"Example-Dict": "a=1, b=2"}, auth=self.auth
        ).prepare()
        parse_dictionary = http_sfv.Dictionary.parse
        with (
            mock.patch.object(http_sfv.Dictionary, "parse", autospec=True, side_effect=parse_dictionary) as dictionary,
            mock.patch.object(resolvers, "parse_qs", wraps=resolvers.parse_qs) as query,
        ):
            self.verify(request, require_components=self.auth.covered_component_ids)
        self.assertEqual(dictionary.call_count, 1)
        self.assertEqual(query.call_count, 1)
        # No cache may survive verification of another message or later edits.
        request.headers["Example-Dict"] = "a=3, b=2"
        with self.assertRaises(InvalidSignature):
            self.verify(request, require_components=self.auth.covered_component_ids)

    def test_associated_request_components_share_a_resolver(self):
        from requests_http_signature import resolvers

        response = self.response()
        response.request.url = "https://example.com/?a=one&b=two"
        components = (
            "@status",
            '"@method";req',
            '"@authority";req',
            '"@query-param";req;name="a"',
            '"@query-param";req;name="b"',
        )
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=components)
        with mock.patch.object(resolvers, "parse_qs", wraps=resolvers.parse_qs) as query:
            self.verify(response, require_components=components, body=b"")
        self.assertEqual(query.call_count, 1)

    def test_header_snapshot_combines_once_and_preserves_wrapping(self):
        from requests_http_signature._headers import message_snapshot

        request = self.request()
        request.headers = HTTPHeaderDict([("X-Value", " one "), ("X-Value", "\ttwo\t")])
        snapshot = message_snapshot(request)
        self.assertEqual(list(snapshot.headers.items()), [("x-value", "one, two")])
        self.assertEqual(snapshot.headers.field_values["x-value"], [" one ", "\ttwo\t"])
        self.assertEqual(request.headers.getlist("X-Value"), [" one ", "\ttwo\t"])

    def test_invalid_digest_members_are_rejected_before_body_hashing(self):
        hashed = []

        def sha256(data=b""):
            if data:
                hashed.append(data)
            return hashlib.sha256(data)

        valid = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(b"body").digest()}))
        with mock.patch.dict(HTTPSignatureAuth._content_digest_hashers, {"sha-256": sha256}):
            for value in (valid + ", unknown=:AA==:", valid + ", sha-512=:AA==:", "sha-256=:AA==:"):
                with self.subTest(value=value), self.assertRaises(InvalidSignature):
                    HTTPSignatureAuth._verify_digest(value, b"body")
        self.assertEqual(hashed, [])


if __name__ == "__main__":
    unittest.main()

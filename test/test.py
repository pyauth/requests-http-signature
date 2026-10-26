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
from urllib.parse import urljoin, urlsplit

import http_sf.compat as http_sfv
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http_message_signatures import (
    ContentDigest,
    HTTPMessageSigner,
    HTTPMessageVerifier,
    InvalidSignature,
    MappingKeyResolver,
)
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
        signer.sign(
            response,
            key_id=default_keyid,
            body=response.raw.getvalue(),
            covered_component_ids=(
                "@status",
                '"@method";req',
                '"@authority";req',
                "content-digest",
                '"@target-uri";req',
            ),
        )
        return response


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
        self.auth.use_existing_digest = True
        for components in ((first, second), ("date", '"date"'), "@method"):
            self.auth.covered_component_ids = components
            with self.assertRaises(HTTPMessageSignaturesException):
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
        self.auth.use_existing_digest = True
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
        self.auth.use_existing_digest = True
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
        self.auth.signer.sign(
            response,
            key_id=default_keyid,
            covered_component_ids=("@status", "content-digest"),
            use_existing_digest=True,
        )
        with self.assertRaisesRegex(InvalidSignature, "Encoded responses require body="):
            self.verify(response, require_components=("@status",))
        raw_body = response.raw.read(decode_content=False)
        result = self.verify(response, require_components=("@status",), body=raw_body)
        self.assertEqual(gzip.decompress(result.body), b"hello")
        with self.assertRaises(InvalidSignature):
            self.verify(response, require_components=("@status",), body=b"hello")

    def test_invalid_digest_fields_raise_invalid_signature(self):
        class UncheckedDigest(ContentDigest):
            @classmethod
            def prepare(cls, headers, body, *, use_existing_digest):
                # Construct signed invalid fields to exercise verification independently of signing checks.
                pass

        self.auth.signer.content_digest_class = UncheckedDigest
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

    def test_selected_digest_member_satisfies_default_body_policy(self):
        component = '"content-digest";key="sha-256"'
        self.auth.covered_component_ids = (*self.auth.covered_component_ids, component)
        request = requests.Request("POST", "https://example.com/", data=b"hello", auth=self.auth).prepare()
        result = self.verify(request)
        self.assertNotIn('"content-digest"', result.covered_components)
        self.assertEqual(result.body, b"hello")
        request.body = b"changed"
        with self.assertRaises(InvalidSignature):
            self.verify(request)

    def test_empty_request_has_a_verified_digest(self):
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                request = requests.Request(method, "https://example.com/", auth=self.auth).prepare()
                self.assertEqual(request.headers["Content-Digest"], ContentDigest.create(b""))
                self.assertEqual(self.verify(request).body, b"")

    def test_existing_digest_requires_opt_in(self):
        digest = ContentDigest.create(b"hello")
        for sign in (self.auth, self.auth.prepare):
            for body in (b"hello", io.BytesIO(b"hello")):
                with self.subTest(sign=sign, body=body):
                    request = requests.Request(
                        "POST", "https://example.com/", data=body, headers={"Content-Digest": digest}
                    ).prepare()
                    with self.assertRaisesRegex(HTTPMessageSignaturesException, "use_existing_digest=True"):
                        sign(request)
                    self.assertNotIn("Signature", request.headers)
                    self.assertEqual(request.headers["Content-Digest"], digest)
                    if isinstance(body, io.BytesIO):
                        self.assertEqual(body.tell(), 0)

    def test_reused_digest_is_preserved_and_revalidated(self):
        self.auth.use_existing_digest = True
        digest = ContentDigest.create(b"hello")
        request = requests.Request(
            "POST", "https://example.com/", data=b"hello", headers={"Content-Digest": digest}, auth=self.auth
        ).prepare()
        self.auth(request)
        self.assertEqual(request.headers["Content-Digest"], digest)
        self.assertEqual(self.verify(request).body, b"hello")
        original_signature = request.headers["Signature"]
        request.body = b"changed"
        with self.assertRaises(InvalidSignature):
            self.auth(request)
        self.assertEqual(request.headers["Signature"], original_signature)

    def test_shared_digest_class_selects_sha512(self):
        class SHA512Digest(ContentDigest):
            algorithm = "sha-512"

        class SHA512Signer(HTTPMessageSigner):
            content_digest_class = SHA512Digest

        class SHA512Auth(HTTPSignatureAuth):
            signer_class = SHA512Signer

        auth = SHA512Auth(key_id=default_keyid, key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)
        for external in (False, True):
            with self.subTest(external=external):
                request = requests.Request("POST", "https://example.com/", data=b"hello").prepare()
                if external:
                    prepared = auth.prepare(request)
                    signature = algorithms.HMAC_SHA256(shared_secret=hmac_secret).sign(prepared.signature_base)
                    auth.apply(request, prepared, signature)
                else:
                    auth(request)
                self.assertEqual(request.headers["Content-Digest"], SHA512Digest.create(b"hello"))
                self.assertEqual(self.verify(request).body, b"hello")

    def test_stream_digest_is_validated_without_consuming_the_stream(self):
        self.auth.use_existing_digest = True
        digest = ContentDigest.create(b"hello")
        for value in ("", "sha-256=1", "sha-256=:AA==:", digest + ", " + digest, "unknown=:aGVsbG8=:"):
            with self.subTest(value=value):
                stream = io.BytesIO(b"prefixhello")
                stream.seek(6)
                request = requests.Request(
                    "POST", "https://example.com/", data=stream, headers={"Content-Digest": value}
                ).prepare()
                with self.assertRaises(InvalidSignature):
                    self.auth(request)
                self.assertEqual(stream.tell(), 6)
                self.assertNotIn("Signature", request.headers)

    def test_response_body_requires_its_own_signed_digest(self):
        response = requests.Response()
        response.request = requests.Request("POST", "https://example.com/", data=b"hello", auth=self.auth).prepare()
        response.status_code = 200
        response._content = b"hello"
        self.auth.signer.sign(response, key_id=default_keyid, covered_component_ids=("@status", '"content-digest";req'))
        with self.assertRaisesRegex(InvalidSignature, "requires a signed Content-Digest"):
            self.verify(response, require_components=("@status",))
        response.headers["Content-Digest"] = ContentDigest.create(b"hello")
        with self.assertRaises(InvalidSignature):
            self.verify(response, require_components=("@status",))
        self.auth.signer.sign(
            response,
            key_id=default_keyid,
            covered_component_ids=("@status",),
            body=b"hello",
            use_existing_digest=True,
        )
        self.assertEqual(self.verify(response, require_components=("@status",)).body, b"hello")

    def test_shared_mapping_resolver_rejects_unknown_key_ids(self):
        self.assertIsInstance(self.auth.signer.key_resolver, MappingKeyResolver)
        auth = HTTPSignatureAuth(key_id="untrusted", key=hmac_secret, signature_algorithm=algorithms.HMAC_SHA256)
        request = requests.Request("GET", "https://example.com/", auth=auth).prepare()
        with self.assertRaises(InvalidSignature):
            self.verify(request)

    def test_required_components_use_upstream_validation(self):
        request = requests.Request("GET", "https://example.com/", auth=self.auth).prepare()
        with self.assertRaises(HTTPMessageSignaturesException):
            self.verify(request, require_components=("@method", '"@method"'))
        with self.assertRaises(InvalidSignature):
            self.verify(request, require_components=("@path",))

    def test_stale_supplied_digest_is_rejected_before_signing(self):
        self.auth.use_existing_digest = True
        with self.assertRaisesRegex(InvalidSignature, "does not match"):
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
        self.auth.use_existing_digest = True
        prepared = self.auth.prepare(first)
        self.auth.apply(first, prepared, algorithm.sign(prepared.signature_base), append_if_signature_exists=True)
        self.assertEqual(self.verify(first, expect_tag="app").label, "second")

    def test_signature_selection(self):
        request = requests.Request("GET", "https://example.com/").prepare()
        self.auth.label, self.auth.tag = "first", "app"
        self.auth(request)
        self.auth.label, self.auth.tag = "second", "other"
        self.auth.append_if_signature_exists = True
        self.auth.use_existing_digest = True
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
        self.auth.use_existing_digest = True
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

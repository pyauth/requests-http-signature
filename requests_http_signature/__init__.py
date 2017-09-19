from __future__ import absolute_import, division, print_function, unicode_literals

import base64, hashlib, hmac, time
import email.utils

import requests
from requests.compat import urlparse

class Crypto:
    def __init__(self, algorithm):
        if algorithm != "hmac-sha256":
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
            from cryptography.hazmat.primitives.hashes import SHA1, SHA256
        self.__dict__.update(locals())

    def sign(self, string_to_sign, key, passphrase=None):
        if self.algorithm == "hmac-sha256":
            return hmac.new(key, string_to_sign, digestmod=hashlib.sha256).digest()
        key = self.load_pem_private_key(key, password=passphrase, backend=self.default_backend())
        if self.algorithm in {"rsa-sha1", "rsa-sha256"}:
            hasher = self.SHA1() if self.algorithm.endswith("sha1") else self.SHA256()
            signer = key.signer(padding=self.PKCS1v15(), algorithm=hasher)
        elif self.algorithm == "ecdsa-sha256":
            signer = key.signer(signature_algorithm=self.ec.ECDSA(algorithm=self.SHA256()))
        signer.update(string_to_sign)
        return signer.finalize()

    def verify(self, signature, string_to_sign, key):
        if self.algorithm == "hmac-sha256":
            assert signature == hmac.new(key, string_to_sign, digestmod=hashlib.sha256).digest()
        else:
            key = self.load_pem_public_key(key, backend=self.default_backend())
            hasher = self.SHA1() if self.algorithm.endswith("sha1") else self.SHA256()
            if self.algorithm == "ecdsa-sha256":
                key.verify(signature, string_to_sign, self.ec.ECDSA(hasher))
            else:
                key.verify(signature, string_to_sign, self.PKCS1v15(), hasher)

class HTTPSignatureAuth(requests.auth.AuthBase):
    hasher_constructor = hashlib.sha256
    known_algorithms = {
        "rsa-sha1",
        "rsa-sha256",
        "hmac-sha256",
        "ecdsa-sha256",
    }

    def __init__(self, key, key_id, algorithm="hmac-sha256", headers=None, passphrase=None):
        assert algorithm in self.known_algorithms
        self.key = key
        self.key_id = key_id
        self.algorithm = algorithm
        self.headers = [h.lower() for h in headers] if headers is not None else ["date"]
        self.passphrase = passphrase if passphrase is None or isinstance(passphrase, bytes) else passphrase.encode()

    def add_date(self, request, timestamp=None):
        if "Date" not in request.headers:
            if timestamp is None:
                timestamp = time.time()
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def add_digest(self, request):
        if request.body is not None and "Digest" not in request.headers:
            if "digest" not in self.headers:
                self.headers.append("digest")
            digest = self.hasher_constructor(request.body).digest()
            request.headers["Digest"] = "SHA-256=" + base64.b64encode(digest).decode()

    @classmethod
    def get_string_to_sign(self, request, headers):
        sts = []
        for header in headers:
            if header == "(request-target)":
                path_url = requests.models.RequestEncodingMixin.path_url.fget(request)
                sts.append("(request-target): {} {}".format(request.method.lower(), path_url))
            else:
                if header.lower() == "host":
                    value = request.headers.get("host", urlparse(request.url).hostname)
                else:
                    value = request.headers[header]
                sts.append("{k}: {v}".format(k=header.lower(), v=value))
        return "\n".join(sts).encode()

    def __call__(self, request):
        self.add_date(request)
        self.add_digest(request)
        raw_sig = Crypto(self.algorithm).sign(string_to_sign=self.get_string_to_sign(request, self.headers),
                                              key=self.key,
                                              passphrase=self.passphrase)
        sig = base64.b64encode(raw_sig).decode()
        sig_struct = [("keyId", self.key_id),
                      ("algorithm", self.algorithm),
                      ("headers", " ".join(self.headers)),
                      ("signature", sig)]
        request.headers["Authorization"] = "Signature " + ",".join('{}="{}"'.format(k, v) for k, v in sig_struct)
        return request

    @classmethod
    def get_sig_struct(self, request):
        scheme, sig_struct = request.headers["Authorization"].split(" ", 1)
        return {i.split("=", 1)[0]: i.split("=", 1)[1].strip('"') for i in sig_struct.split(",")}

    @classmethod
    def verify(self, request, key_resolver):
        assert "Authorization" in request.headers, "No Authorization header found"
        msg = 'Unexpected scheme found in Authorization header (expected "Signature")'
        assert request.headers["Authorization"].startswith("Signature "), msg
        sig_struct = self.get_sig_struct(request)
        for field in "keyId", "algorithm", "signature":
            assert field in sig_struct, 'Required signature parameter "{}" not found'.format(field)
        assert sig_struct["algorithm"] in self.known_algorithms, "Unknown signature algorithm"
        headers = sig_struct.get("headers", "date").split(" ")
        sig = base64.b64decode(sig_struct["signature"])
        sts = self.get_string_to_sign(request, headers)
        key = key_resolver(key_id=sig_struct["keyId"], algorithm=sig_struct["algorithm"])
        Crypto(sig_struct["algorithm"]).verify(sig, sts, key)

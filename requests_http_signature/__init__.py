from __future__ import absolute_import, division, print_function, unicode_literals

import base64, hashlib, hmac, time
import email.utils

import requests
from requests.compat import urlparse
from requests.exceptions import RequestException

class RequestsHttpSignatureException(RequestException):
    """An error occurred while constructing the HTTP Signature for your request."""

class Crypto:
    def __init__(self, algorithm):
        if algorithm != "hmac-sha256":
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
            from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
        self.__dict__.update(locals())

    def sign(self, string_to_sign, key, passphrase=None):
        if self.algorithm == "hmac-sha256":
            return hmac.new(key, string_to_sign, digestmod=hashlib.sha256).digest()
        key = self.load_pem_private_key(key, password=passphrase, backend=self.default_backend())
        if self.algorithm in {"rsa-sha1", "rsa-sha256"}:
            hasher = self.SHA1() if self.algorithm.endswith("sha1") else self.SHA256()
            return key.sign(padding=self.PKCS1v15(), algorithm=hasher, data=string_to_sign)
        elif self.algorithm in {"rsa-sha512"}:
            hasher = self.SHA512()
            return key.sign(padding=self.PKCS1v15(), algorithm=hasher, data=string_to_sign)
        elif self.algorithm == "ecdsa-sha256":
            return key.sign(signature_algorithm=self.ec.ECDSA(algorithm=self.SHA256()), data=string_to_sign)

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
        "rsa-sha512",
        "hmac-sha256",
        "ecdsa-sha256",
    }

    def __init__(self, key, key_id, algorithm="hmac-sha256", headers=None, passphrase=None, expires_in=None):
        """
        :param typing.Union[bytes, string] passphrase: The passphrase for an encrypted RSA private key
        :param datetime.timedelta expires_in: The time after which this signature should expire
        """
        assert algorithm in self.known_algorithms
        self.key = key
        self.key_id = key_id
        self.algorithm = algorithm
        self.headers = [h.lower() for h in headers] if headers is not None else ["date"]
        self.passphrase = passphrase if passphrase is None or isinstance(passphrase, bytes) else passphrase.encode()
        self.expires_in = expires_in

    def add_date(self, request, timestamp):
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def add_digest(self, request):
        if request.body is None and "digest" in self.headers:
            raise RequestsHttpSignatureException("Could not compute digest header for request without a body")
        if request.body is not None and "Digest" not in request.headers:
            if "digest" not in self.headers:
                self.headers.append("digest")
            digest = self.hasher_constructor(request.body).digest()
            request.headers["Digest"] = "SHA-256=" + base64.b64encode(digest).decode()

    @classmethod
    def get_string_to_sign(self, request, headers, created_timestamp, expires_timestamp):
        sts = []
        for header in headers:
            if header == "(request-target)":
                path_url = requests.models.RequestEncodingMixin.path_url.fget(request)
                sts.append("{}: {} {}".format(header, request.method.lower(), path_url))
            elif header == "(created)":
                sts.append("{}: {}".format(header, created_timestamp))
            elif header == "(expires)":
                assert (expires_timestamp is not None), \
                    'You should provide the "expires_in" argument when using the (expires) header'
                sts.append("{}: {}".format(header, int(expires_timestamp)))
            else:
                if header.lower() == "host":
                    url = urlparse(request.url)
                    value = request.headers.get("host", url.hostname)
                    if url.scheme == "http" and url.port not in [None, 80] or url.scheme == "https" \
                            and url.port not in [443, None]:
                        value = "{}:{}".format(value, url.port)
                else:
                    value = request.headers[header]
                sts.append("{k}: {v}".format(k=header.lower(), v=value))
        return "\n".join(sts).encode()

    def create_signature_string(self, request):
        created_timestamp = int(time.time())
        expires_timestamp = None
        if self.expires_in is not None:
            expires_timestamp = created_timestamp + self.expires_in.total_seconds()
        self.add_date(request, created_timestamp)
        self.add_digest(request)
        raw_sig = Crypto(self.algorithm).sign(
            string_to_sign=self.get_string_to_sign(request, self.headers, created_timestamp, expires_timestamp),
            key=self.key.encode() if isinstance(self.key, str) else self.key,
            passphrase=self.passphrase,
        )
        sig = base64.b64encode(raw_sig).decode()
        sig_struct = [
            ("keyId", self.key_id),
            ("algorithm", self.algorithm),
            ("headers", " ".join(self.headers)),
            ("signature", sig),
            ("created", int(created_timestamp)),
        ]
        if expires_timestamp is not None:
            sig_struct.append(("expires", int(expires_timestamp)))
        return ",".join('{}="{}"'.format(k, v) for k, v in sig_struct)

    def __call__(self, request):
        request.headers["Authorization"] = "Signature " + self.create_signature_string(request)
        return request

    @classmethod
    def get_sig_struct(self, request, scheme="Authorization"):
        sig_struct = request.headers[scheme]
        if scheme == "Authorization":
            sig_struct = sig_struct.split(" ", 1)[1]
        return {i.split("=", 1)[0]: i.split("=", 1)[1].strip('"') for i in sig_struct.split(",")}

    @classmethod
    def verify(self, request, key_resolver, scheme="Authorization"):
        if scheme == "Authorization":
            assert "Authorization" in request.headers, "No Authorization header found"
            msg = 'Unexpected scheme found in Authorization header (expected "Signature")'
            assert request.headers["Authorization"].startswith("Signature "), msg
        elif scheme == "Signature":
            assert "Signature" in request.headers, "No Signature header found"
        else:
            raise RequestsHttpSignatureException('Unknown signature scheme "{}"'.format(scheme))

        sig_struct = self.get_sig_struct(request, scheme=scheme)
        for field in "keyId", "algorithm", "signature":
            assert field in sig_struct, 'Required signature parameter "{}" not found'.format(field)
        assert sig_struct["algorithm"] in self.known_algorithms, "Unknown signature algorithm"
        created_timestamp = int(sig_struct['created'])
        expires_timestamp = sig_struct.get('expires')
        if expires_timestamp is not None:
            expires_timestamp = int(expires_timestamp)
        headers = sig_struct.get("headers", "date").split(" ")
        sig = base64.b64decode(sig_struct["signature"])
        sts = self.get_string_to_sign(request, headers, created_timestamp, expires_timestamp=expires_timestamp)
        key = key_resolver(key_id=sig_struct["keyId"], algorithm=sig_struct["algorithm"])
        Crypto(sig_struct["algorithm"]).verify(sig, sts, key)

class HTTPSignatureHeaderAuth(HTTPSignatureAuth):
    """
        https://tools.ietf.org/html/draft-cavage-http-signatures-08#section-4
        Using "Signature" header instead of "Authorization" header.
    """

    def __call__(self, request):
        request.headers["Signature"] = self.create_signature_string(request)
        return request

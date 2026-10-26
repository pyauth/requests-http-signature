import datetime
import email.utils
import io
import secrets
from collections.abc import Sequence
from typing import Any, BinaryIO, ClassVar, cast

import requests
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureComponentResolver,
    HTTPSignatureKeyResolver,
    MappingKeyResolver,
)
from http_message_signatures import InvalidSignature as InvalidSignature
from http_message_signatures import PreparedSignature as PreparedSignature
from http_message_signatures import VerifyResult as VerifyResult
from http_message_signatures import algorithms as algorithms
from http_message_signatures.structures import get_header_fields
from requests.exceptions import RequestException
from urllib3.response import HTTPResponse


class _BufferedHTTPResponse(HTTPResponse):
    """Replay captured content through urllib3's normal content decoders."""

    def __init__(self, original: HTTPResponse, body: bytes):
        super().__init__(
            body=io.BytesIO(body),
            headers=original.headers,
            status=original.status,
            version=original.version,
            reason=original.reason,
            retries=original.retries,
            request_url=original.geturl(),
            preload_content=False,
            decode_content=False,
        )
        self._signature_body = body


class RequestsHttpSignatureException(RequestException):
    """An error occurred while constructing the HTTP Signature for your request."""


class HTTPSignatureAuth(requests.auth.AuthBase):
    """
    A `Requests <https://github.com/requests/requests>`_ `authentication plugin
    <http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass)
    implementing `RFC 9421, HTTP Message Signatures <https://www.rfc-editor.org/rfc/rfc9421.html>`_.

    :param signature_algorithm:
        One of ``requests_http_signature.algorithms.HMAC_SHA256``,
        ``requests_http_signature.algorithms.ECDSA_P256_SHA256``,
        ``requests_http_signature.algorithms.ED25519``,
        ``requests_http_signature.algorithms.RSA_PSS_SHA512``, or
        ``requests_http_signature.algorithms.RSA_V1_5_SHA256``.
    :param key:
        Key material that will be used to sign the request. In the case of HMAC, this should be the raw bytes of the
        shared secret; for all other algorithms, this should be the bytes of the PEM-encoded private key material.
    :param key_id: The key ID to use in the signature.
    :param key_resolver:
        Instead of specifying a fixed key, you can instead pass a key resolver, which should be an instance of a
        subclass of ``http_message_signatures.HTTPSignatureKeyResolver``. A key resolver should have two methods,
        ``resolve_private_key(key_id)`` (required only for signing) and ``resolve_public_key(key_id)`` (required only for
        verifying). Your implementation should ensure that the key id is recognized and return the corresponding
        key material as PEM bytes, cryptography key objects, or shared secret bytes for HMAC.
        Omit both ``key`` and ``key_resolver`` when using ``prepare()`` and ``apply()`` with an external signer.
    :param covered_component_ids:
        Lowercase header names or serialized RFC 9421 component identifiers. Request derived components include
        ``@method``, ``@target-uri``, ``@authority``, ``@scheme``, ``@request-target``, ``@path``, ``@query``, and
        ``'"@query-param";name="Pet"'``. Parameter values are case-sensitive; their order does not affect identity.
        Duplicate component identifiers are rejected. Defaults to ``@method``, ``@authority``, and ``@target-uri``.
        ``Authorization`` and ``Date`` are also covered when present. The signer adds digest coverage for
        buffered content, including empty requests. Explicit digest-member coverage, such as
        ``'"content-digest";key="sha-256"'``, replaces automatic whole-field coverage for buffered content.
        Streams always cover the whole supplied Content-Digest field.
    :param label: The signature dictionary label, which is not signed.
    :param tag: A signed application tag, usable with ``verify(expect_tag=...)``.
    :param append_if_signature_exists: Append a distinct signature label instead of replacing existing signatures.
    :param include_alg:
        By default, the signature parameters will include the ``alg`` parameter, using it to identify the signature
        algorithm. If you wish not to include this parameter, set this to ``False``.
    :param use_nonce:
        Set this to ``True`` to include a unique message-specific nonce in the signature parameters. The format of
        the nonce can be controlled by subclassing this class and overloading the ``get_nonce()`` method.
    :param expires_in:
        Use this to set the ``expires`` signature parameter to the time of signing plus the given timedelta.
    :param use_existing_digest:
        Allow a supplied Content-Digest, validating it against buffered bytes before signing.
        Required for streams with precomputed digests and when signing a request again.
    """

    component_resolver_class: type[HTTPSignatureComponentResolver] = HTTPSignatureComponentResolver
    """
    A subclass of ``http_message_signatures.HTTPSignatureComponentResolver`` can be used to override this value
    to customize the retrieval of header and derived component values if needed.
    """

    verifier_class: type[HTTPMessageVerifier] = HTTPMessageVerifier
    "A verifier subclass can configure creation-time requirements and clock-skew tolerance."

    signer_class: type[HTTPMessageSigner] = HTTPMessageSigner
    "A signer subclass can select a ContentDigest subclass through its content_digest_class attribute."

    _auto_cover_header_fields: ClassVar[tuple[str, ...]] = ("authorization", "date")

    @staticmethod
    def _validate_header_names(message: requests.PreparedRequest | requests.Response) -> None:
        seen = set()
        for name in message.headers:
            if name.lower() in seen:
                raise RequestsHttpSignatureException(f"Multiple header values match {name!r} case-insensitively")
            seen.add(name.lower())

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key: bytes | None = None,
        key_id: str,
        key_resolver: HTTPSignatureKeyResolver | None = None,
        covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
        label: str | None = None,
        tag: str | None = None,
        append_if_signature_exists: bool = False,
        include_alg: bool = True,
        use_nonce: bool = False,
        expires_in: datetime.timedelta | None = None,
        use_existing_digest: bool = False,
    ) -> None:
        if key_resolver is not None and key is not None:
            raise RequestsHttpSignatureException("Either key_resolver or key must be specified, not both.")
        if key is not None:
            key_resolver = MappingKeyResolver(private_keys={key_id: key}, public_keys={key_id: key})

        self.key_id = key_id
        self.label = label
        self.tag = tag
        self.append_if_signature_exists = append_if_signature_exists
        self.include_alg = include_alg
        self.use_nonce = use_nonce
        self.covered_component_ids = covered_component_ids
        self.expires_in = expires_in
        self.use_existing_digest = use_existing_digest
        self.signer = self.signer_class(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=self.component_resolver_class,
        )

    def add_date(self, request: requests.PreparedRequest, timestamp: int) -> None:
        if "Date" not in request.headers:
            request.headers["Date"] = email.utils.formatdate(timestamp, usegmt=True)

    def _signing_body(self, request: requests.PreparedRequest) -> bytes | None:
        self._validate_header_names(request)
        request.headers = requests.structures.CaseInsensitiveDict(request.headers)
        if isinstance(request.body, str):
            request.body = request.body.encode("utf-8")
        elif isinstance(request.body, (bytearray, memoryview)):
            request.body = bytes(request.body)
        if request.body is not None and not isinstance(request.body, bytes):
            if "Content-Digest" not in request.headers:
                raise RequestsHttpSignatureException(
                    "Streaming bodies require a precomputed Content-Digest header; the stream is not read or rewound"
                )
            return None
        return request.body or b""

    def get_nonce(self, request: requests.PreparedRequest) -> str | None:
        if self.use_nonce:
            return secrets.token_urlsafe(16)
        return None

    def get_created(self, request: requests.PreparedRequest) -> datetime.datetime:
        created = datetime.datetime.now()
        self.add_date(request, timestamp=int(created.timestamp()))
        return created

    def get_expires(self, request: requests.PreparedRequest, created: datetime.datetime) -> datetime.datetime | None:
        if self.expires_in is not None:
            return created + self.expires_in
        return None

    def get_covered_component_ids(self, request: requests.PreparedRequest) -> Sequence[str]:
        if isinstance(self.covered_component_ids, (str, bytes, bytearray)):
            return self.covered_component_ids
        components = list(self.covered_component_ids)
        auto_cover = self._auto_cover_header_fields
        if request.body is not None and not isinstance(request.body, bytes):
            auto_cover += ("content-digest",)
        for header in auto_cover:
            if header in request.headers and header not in components and f'"{header}"' not in components:
                components.append(header)
        return components

    def _signing_options(self, request: requests.PreparedRequest) -> dict[str, Any]:
        body = self._signing_body(request)
        created = self.get_created(request)
        return {
            "key_id": self.key_id,
            "created": created,
            "expires": self.get_expires(request, created=created),
            "nonce": self.get_nonce(request),
            "label": self.label,
            "tag": self.tag,
            "include_alg": self.include_alg,
            "covered_component_ids": self.get_covered_component_ids(request),
            "body": body,
            "use_existing_digest": self.use_existing_digest,
        }

    def prepare(self, request: requests.PreparedRequest) -> PreparedSignature:
        """Set digest/date headers and return signing input without resolving a key.

        Use a fully prepared Requests request. Keep the returned object with this
        request while an external signer signs its ``signature_base`` bytes.
        """
        return self.signer.prepare(request, **self._signing_options(request))

    def apply(
        self,
        request: requests.PreparedRequest,
        prepared: PreparedSignature,
        signature: bytes,
        *,
        append_if_signature_exists: bool | None = None,
    ) -> requests.PreparedRequest:
        """Attach raw signature bytes and return the request ready for ``Session.send``.

        Covered values must still match preparation. Buffered bodies are checked
        against their digest; callers supplying stream digests must keep the stream
        unchanged. This does not verify the external signature or refresh its age.
        """
        self._validate_header_names(request)
        headers = get_header_fields(request.headers)
        if "Content-Digest" in headers and (
            request.body is None or isinstance(request.body, (str, bytes, bytearray, memoryview))
        ):
            self.signer.content_digest_class.verify(headers["Content-Digest"], self.get_body(request))
        self.signer.apply(
            request,
            prepared,
            signature,
            append_if_signature_exists=(
                self.append_if_signature_exists if append_if_signature_exists is None else append_if_signature_exists
            ),
        )
        return request

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.signer.key_resolver is None:
            raise RequestsHttpSignatureException(
                "Local signing requires a key or key_resolver; use prepare()/apply() otherwise"
            )
        self.signer.sign(
            request,
            append_if_signature_exists=self.append_if_signature_exists,
            **self._signing_options(request),
        )
        return request

    @classmethod
    def get_body(cls, message: requests.PreparedRequest | requests.Response) -> bytes:
        """Read content for digest verification, preserving buffered responses and seekable request bodies.

        Compressed responses must be requested with ``stream=True``. Their encoded content is buffered internally
        and remains available to Requests for normal decoding. Seekable binary request bodies are read from the
        starting position recorded by Requests, then restored to their current position.
        """
        if isinstance(message, requests.Response):
            if (
                message.status_code in (204, 304)
                or 100 <= message.status_code < 200
                or (message.request is not None and message.request.method == "HEAD")
            ):
                return b""
            if isinstance(message.raw, _BufferedHTTPResponse):
                return message.raw._signature_body
            headers = requests.structures.CaseInsensitiveDict(message.headers)
            if headers.get("Content-Encoding", "identity").lower() != "identity":
                if message._content is not False or message._content_consumed:
                    raise InvalidSignature("Encoded response content is no longer available; request stream=True")
                if not isinstance(message.raw, HTTPResponse):
                    raise InvalidSignature("Encoded response verification requires an unread urllib3 response")
                # tell() alone does not account for urllib3's chunked reads.
                if message.raw.tell() != 0 or message.raw._uncached_read_occurred:
                    raise InvalidSignature("Response body was partially consumed before verification")
                body = message.raw.read(decode_content=False)
                message.raw = _BufferedHTTPResponse(message.raw, body)
                return body
            if message._content is False:
                if message._content_consumed:
                    raise InvalidSignature("Response body was consumed before verification")
                if isinstance(message.raw, HTTPResponse) and message.raw._uncached_read_occurred:
                    raise InvalidSignature("Response body was partially consumed before verification")
                if isinstance(message.raw, (HTTPResponse, io.IOBase)) and message.raw.tell() != 0:
                    raise InvalidSignature("Response body was partially consumed before verification")
            content = message.content
            return b"" if content is None else content
        if isinstance(message.body, str):
            return message.body.encode("utf-8")
        if isinstance(message.body, (bytes, bytearray, memoryview)):
            return bytes(message.body)
        if message.body is None:
            return b""
        if not isinstance(message._body_position, int):
            raise InvalidSignature("Request verification requires a buffered or seekable binary body")
        stream = cast(BinaryIO, message.body)
        try:
            position = stream.tell()
            stream.seek(message._body_position)
        except (AttributeError, OSError, ValueError) as exc:
            raise InvalidSignature("Request verification requires a buffered or seekable binary body") from exc
        try:
            body = stream.read()
        finally:
            stream.seek(position)
        if not isinstance(body, bytes):
            raise InvalidSignature("Verification requires body bytes")
        return body

    @classmethod
    def verify(
        cls,
        message: requests.PreparedRequest | requests.Response,
        *,
        require_components: Sequence[str] | None = None,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver,
        max_age: datetime.timedelta | None = datetime.timedelta(days=1),
        expect_tag: str | None = None,
        expect_label: str | None = None,
    ) -> VerifyResult:
        """
        Verify an HTTP message signature and its body digest using content read from the message.

        Request compressed responses with ``stream=True`` so this method can read their encoded content.
        It buffers that content internally and preserves Requests' normal ``content``, ``text``, and ``json()``
        access after verification. Already decoded or partially consumed response streams cannot be verified.
        Buffered requests and seekable binary request bodies are read automatically; seekable bodies retain
        their current position. Missing unencoded response content is treated as empty bytes.

        .. admonition:: See what is signed

         It is important to understand and follow the best practice rule of "See what is signed" when verifying HTTP
         message signatures. The gist of this rule is: if your application neglects to verify that the information it
         trusts is what was actually signed, the attacker can supply a valid signature but point you to malicious data
         that wasn't signed by that signature. Failure to follow this rule can lead to vulnerability against signature
         wrapping and substitution attacks.

         You can ensure that the information signed is what you expect to be signed by only trusting the *VerifyResult*
         tuple returned by ``verify()``.

        :param message:
            The HTTP response or request to verify. You can either pass a received response, or reconstruct an arbitrary
            request using the `Requests API <https://docs.python-requests.org/en/latest/api/#requests.Request>`_::

              request = requests.Request(...)
              prepared_request = request.prepare()
              HTTPSignatureAuth.verify(prepared_request, ...)

        :param require_components:
            Lowercase header names or serialized component identifiers whose coverage is required. Parameter order
            is ignored for comparison, but parameter values retain their case and types. Duplicate identifiers fail.
            The request default is ``("@method", "@authority", "@target-uri")``. The response default is
            ``("@status", '"@method";req', '"@authority";req', '"@target-uri";req')``, binding the response to its request.
            Supply a different profile explicitly if your peer signs other components.

            Nonempty content, or a present Content-Digest field, additionally requires a covered content digest.
            A selected digest dictionary member is sufficient. Empty messages do not require an absent digest;
            any present digest is still verified, including the digest of empty content. Request components with
            ``;req`` do not satisfy coverage of the response body. Validation returns the bytes in ``result.body``.
        :param signature_algorithm:
            The algorithm expected to be used by the signature. Any signature not using the expected algorithm will
            cause an ``InvalidSignature`` exception. Must be one of ``requests_http_signature.algorithms.HMAC_SHA256``,
            ``requests_http_signature.algorithms.ECDSA_P256_SHA256``,
            ``requests_http_signature.algorithms.ED25519``,
            ``requests_http_signature.algorithms.RSA_PSS_SHA512``, or
            ``requests_http_signature.algorithms.RSA_V1_5_SHA256``.
        :param key_resolver:
            A key resolver, which should be an instance of a subclass of
            ``http_message_signatures.HTTPSignatureKeyResolver``. A key resolver should have two methods,
            ``resolve_private_key(key_id)`` (required only for signing) and ``resolve_public_key(key_id)`` (required only for
            verifying). Your implementation should ensure that the key id is recognized and return the corresponding
            key material as PEM bytes (or shared secret bytes for HMAC).
        :param max_age:
            Maximum age since ``created``; ``None`` disables this limit, but expiration is still checked.
            Customize ``verifier_class`` to change its ``require_created`` and ``max_clock_skew`` policies.
        :param expect_tag: Select a signed application tag. Selection must leave one verified signature.
        :param expect_label: Further select the dictionary label; requires ``expect_tag`` under the default policy.

        :returns: *VerifyResult*, a namedtuple with the following attributes:

            * ``label`` (str): The label for the signature
            * ``algorithm``: (same as ``signature_algorithm`` above)
            * ``covered_components``: A mapping of component names to their values, as covered by the signature
            * ``parameters``: A mapping of signature parameters to their values, as covered by the signature, including
              "alg", "created", "expires", "keyid", and "nonce". To protect against replay attacks, retrieve the "nonce"
              parameter here and check that it has not been seen before.
            * ``nonce``: The signed nonce, or ``None``. Applications must enforce replay detection.
            * ``body``: Content bytes before decoding, after validating their covered digest; ``None`` otherwise.

        :raises InvalidSignature: Signature, required coverage, or body-digest validation fails.
        :raises HTTPMessageSignaturesException: The algorithm, required components, or selection policy is invalid.
        """
        if require_components is None:
            require_components = (
                ("@status", '"@method";req', '"@authority";req', '"@target-uri";req')
                if isinstance(message, requests.Response)
                else ("@method", "@authority", "@target-uri")
            )
        try:
            cls._validate_header_names(message)
        except RequestsHttpSignatureException as e:
            raise InvalidSignature(str(e)) from e
        verifier = cls.verifier_class(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=cls.component_resolver_class,
        )
        verify_results = verifier.verify(
            message,
            max_age=max_age,
            expect_tag=expect_tag,
            expect_label=expect_label,
            require_components=require_components,
        )
        if len(verify_results) != 1:
            raise InvalidSignature("Select a single signature using expect_tag and expect_label")
        body = cls.get_body(message)
        if not isinstance(body, bytes):
            raise InvalidSignature("Verification requires body bytes")
        return verifier.verify_body(message, verify_results, body)[0]

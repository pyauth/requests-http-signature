requests-http-signature: A Requests auth module for HTTP Signature
==================================================================
**requests-http-signature** is a `Requests <https://github.com/requests/requests>`_ `authentication plugin
<http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass) implementing
the
`IETF RFC 9421 HTTP Message Signatures standard <https://datatracker.ietf.org/doc/rfc9421/>`_.

Installation
------------
::

    $ pip install requests-http-signature

Requires Requests 2.34.2 or later and http-message-signatures 2.1.0 or later. The signing, verification, and
external-signing examples below use the APIs published in http-message-signatures 2.1.0.

Usage
-----

.. code-block:: python

  import requests
  from http_message_signatures import HTTPSignatureKeyResolver
  from requests_http_signature import HTTPSignatureAuth, algorithms
  
  preshared_key_id = 'squirrel'
  preshared_secret = b'monorail_cat'
  url = 'https://example.com/'

  auth = HTTPSignatureAuth(key=preshared_secret,
                           key_id=preshared_key_id,
                           signature_algorithm=algorithms.HMAC_SHA256)
  requests.get(url, auth=auth, allow_redirects=False)

By default, only the ``Date`` header and the ``@method``, ``@authority``, and ``@target-uri`` derived component
identifiers are signed for body-less requests such as GET. The ``Date`` header is set if it is absent. In addition,
the ``Authorization`` header is signed if it is present, and for requests with bodies (such as POST), the
``Content-Digest`` header is set to the SHA256 of the request body using the format described in the
`RFC 9530, Digest Fields <https://www.rfc-editor.org/rfc/rfc9530.html>`_ and signed.
To add other headers to the signature, pass an array of header names in the ``covered_component_ids`` keyword argument.
See the `API documentation <https://pyauth.github.io/requests-http-signature/#id3>`_ for the full list of options and
details.

Verifying responses
~~~~~~~~~~~~~~~~~~~
The class method ``HTTPSignatureAuth.verify()`` can be used to verify responses received back from the server:

.. code-block:: python

  class MyKeyResolver(HTTPSignatureKeyResolver):
      def resolve_public_key(self, key_id):
          assert key_id == 'squirrel'
          return b'monorail_cat'

  with requests.get(url, auth=auth, stream=True, allow_redirects=False) as response:
      encoded_body = response.raw.read(decode_content=False)
      verify_result = HTTPSignatureAuth.verify(response,
                                              signature_algorithm=algorithms.HMAC_SHA256,
                                              key_resolver=MyKeyResolver(),
                                              body=encoded_body)

Response verification requires ``@status`` plus ``"@method";req``, ``"@authority";req``, and
``"@target-uri";req`` by default. The ``req`` flag binds the response to its associated request.
The server must sign these components; bare request-derived components are invalid in response signatures.
If your protocol uses a different coverage profile, pass it explicitly as ``require_components``.

``Content-Digest`` covers bytes before content decoding. Requests normally decompresses ``response.content``;
the ``stream=True`` workflow above preserves the bytes needed for verification, including gzip or Brotli content.
Do not access ``response.content`` or ``iter_content()`` before capturing them. Decode ``verify_result.body`` only
after verification. ``body=`` must refer to content captured from this response, not another response or a decoded copy.
For unencoded responses, ``body`` may be omitted and ``verify()`` reads ``response.content`` into memory.
These APIs buffer content; they do not provide incremental verification for arbitrarily large downloads.

Nonempty content requires a covered digest. Empty responses, including HEAD, 204, and 304, do not require a digest
unless it is explicitly required or present. When present, a covered digest of empty content is verified as well.

More generally, you can reconstruct an arbitrary request using the
`Requests API <https://docs.python-requests.org/en/latest/api/#requests.Request>`_ and pass it to ``verify()``:

.. code-block:: python

  request = requests.Request(...)  # Reconstruct the incoming request using the Requests API
  prepared_request = request.prepare()  # Generate a PreparedRequest
  HTTPSignatureAuth.verify(prepared_request, ...)

To verify incoming requests and sign responses in the context of an HTTP server, see the
`flask-http-signature <https://github.com/pyauth/flask-http-signature>`_ and
`http-message-signatures <https://github.com/pyauth/http-message-signatures>`_ packages.

.. admonition:: See what is signed

 It is important to understand and follow the best practice rule of "See what is signed" when verifying HTTP message
 signatures. The gist of this rule is: if your application neglects to verify that the information it trusts is
 what was actually signed, the attacker can supply a valid signature but point you to malicious data that wasn't signed
 by that signature. Failure to follow this rule can lead to vulnerability against signature wrapping and substitution
 attacks.

 In requests-http-signature, you can ensure that the information signed is what you expect to be signed by only trusting
 the data returned by the ``verify()`` method::

   verify_result = HTTPSignatureAuth.verify(message, ...)

See the `API documentation <https://pyauth.github.io/requests-http-signature/#id3>`_ for full details.

Asymmetric key algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~
To sign or verify messages with an asymmetric key algorithm, set the ``signature_algorithm`` keyword argument to
``algorithms.ED25519``, ``algorithms.ECDSA_P256_SHA256``, ``algorithms.RSA_V1_5_SHA256``, or
``algorithms.RSA_PSS_SHA512``.

For asymmetric key algorithms, you can supply the private key as the ``key`` parameter to the ``HTTPSignatureAuth()``
constructor as bytes in the PEM format, or configure the key resolver as follows:

.. code-block:: python

  with open('key.pem', 'rb') as fh:
      auth = HTTPSignatureAuth(signature_algorithm=algorithms.RSA_V1_5_SHA256,
                               key=fh.read(),
                               key_id=preshared_key_id)
  requests.get(url, auth=auth, allow_redirects=False)

  class MyKeyResolver(HTTPSignatureKeyResolver):
      def resolve_public_key(self, key_id: str):
          return public_key_pem_bytes[key_id]

      def resolve_private_key(self, key_id: str):
          return private_key_pem_bytes[key_id]

  auth = HTTPSignatureAuth(signature_algorithm=algorithms.RSA_V1_5_SHA256,
                           key_resolver=MyKeyResolver(),
                           key_id="my-key-id")
  requests.get(url, auth=auth, allow_redirects=False)

Digest algorithms
~~~~~~~~~~~~~~~~~
To generate a Content-Digest header using SHA-512 instead of the default SHA-256, subclass ``HTTPSignatureAuth`` as
follows::

  class MySigner(HTTPSignatureAuth):
      signing_content_digest_algorithm = "sha-512"

Request bodies and streams
~~~~~~~~~~~~~~~~~~~~~~~~~~
Bytes, text, form dictionaries, JSON, and Requests' buffered multipart uploads are supported. Text is encoded as
UTF-8 before hashing and sending. A supplied Content-Digest is checked against buffered content before signing.

File objects and iterators require a caller-supplied Content-Digest for the bytes that will be sent from their current
position. The auth handler does not read, consume, buffer, or rewind these streams. For example::

  import hashlib
  import io
  from http_sf.compat import Dictionary

  payload = b"upload content"
  digest = str(Dictionary({"sha-256": hashlib.sha256(payload).digest()}))
  response = requests.post(url, data=io.BytesIO(payload), headers={"Content-Digest": digest},
                           auth=auth, allow_redirects=False)

Keep a streaming body unchanged after computing its digest. To verify a streaming request, pass its transmitted bytes
as ``body=``; verification does not consume the stream. Unsupported streams without a supplied digest raise
``RequestsHttpSignatureException``. Malformed, duplicate, wrongly typed, unsupported, or mismatched digests during
verification raise ``InvalidSignature``.

Component identifiers
~~~~~~~~~~~~~~~~~~~~~
Use lowercase component names. Individual query parameters use ``@query-param`` with a ``name`` parameter::

  components = ('"@query-param";name="Foo"', '"@query-param";name="foo"')
  query_auth = HTTPSignatureAuth(key_id=preshared_key_id, key=preshared_secret,
                           signature_algorithm=algorithms.HMAC_SHA256,
                           covered_component_ids=components)

The two query names above are distinct and both are signed. Component identity includes parameter values but ignores
parameter order, as specified in RFC 9421 section 2. Duplicate identifiers, including ``date`` and ``"date"``, are errors.
When a supplied header container exposes names more than once under case-insensitive matching, the package raises an
error instead of choosing a value. It cannot recover field lines already discarded by a header container.

Dictionary-member coverage such as ``'"content-digest";key="sha-256";sf'`` is supported. Its parameter order may differ
in ``require_components``; the signed wire order is preserved. A covered digest member suffices for body validation
without requiring the whole Content-Digest field. ``@request-response`` and unsupported Structured Field flags are
not implemented.

External signing
~~~~~~~~~~~~~~~~
Use ``prepare()`` and ``apply()`` on a fully prepared Requests request when a remote service holds the private key.
No local key or resolver is needed. The auth object prepares the body digest, Date, covered components, nonce, and
creation/expiration parameters, then returns a ``PreparedSignature``::

  session = requests.Session()
  external_auth = HTTPSignatureAuth(key_id="remote-ed25519-key", signature_algorithm=algorithms.ED25519, tag="my-app")
  request = session.prepare_request(requests.Request("POST", url, json={"hello": "world"}))
  prepared = external_auth.prepare(request)
  signature = sign_base(prepared.signature_base)  # Your service signs these bytes with Ed25519.
  external_auth.apply(request, prepared, signature)
  response = session.send(request, allow_redirects=False)

For an asynchronous signer, await ``sign_base(prepared.signature_base)`` between preparation and application.
Requests' send operation remains synchronous. Do not pass a keyless auth object through ``auth=``: that path performs
local signing. Use a session without another request-signing auth handler when preparing the request externally.

``apply()`` accepts raw signature bytes, checks covered headers and buffered body digests for changes, and returns the
request. It does not authenticate the external service, verify its signature, refresh timestamps, or validate a stream
against a supplied digest. Keep the prepared object associated with the right request and keep that request stable
until sending. For DER-encoded ECDSA output, use ``algorithms.ECDSA_P256_SHA256.signature_from_der()`` before applying it.
See the `http-message-signatures external-signing documentation
<https://github.com/pyauth/http-message-signatures/tree/v2.1.0#remote-and-asynchronous-signing>`_ for algorithm input requirements.

Signature selection and verification policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Set a signed application ``tag`` when signing. To preserve another signature, also choose a distinct ``label`` and set
``append_if_signature_exists=True`` on the auth object or its ``apply()`` call. During verification::

  result = HTTPSignatureAuth.verify(message, signature_algorithm=algorithms.HMAC_SHA256,
                                    key_resolver=MyKeyResolver(), expect_tag="my-app", expect_label="sig1")

Selection must leave one verified signature. Labels are not signed, so the default policy requires ``expect_tag`` when
``expect_label`` is used. Use ``result.nonce`` to enforce your application's replay policy.

``max_age=None`` disables the age limit but retains expiration checks. Customize the existing verifier class to change
creation-time requirements or clock skew::

  import datetime
  from http_message_signatures import HTTPMessageVerifier

  class MyVerifier(HTTPMessageVerifier):
      require_created = False
      max_clock_skew = datetime.timedelta(seconds=30)

  class MyAuth(HTTPSignatureAuth):
      verifier_class = MyVerifier

  result = MyAuth.verify(message, signature_algorithm=algorithms.HMAC_SHA256,
                         key_resolver=MyKeyResolver(), max_age=None)

Redirects
~~~~~~~~~
Pass ``allow_redirects=False`` for signed requests. Requests copies signature headers while following redirects and
does not re-run custom auth handlers; changing the URL or method invalidates the signature. Automatic redirect
re-signing is not provided. Decide whether to follow each destination, then prepare and sign a fresh request.
For example, this GET-only flow permits one redirect within the original origin::

  from urllib.parse import urljoin, urlsplit

  response = requests.get(url, auth=auth, allow_redirects=False)
  if response.is_redirect:
      destination = urljoin(response.url, response.headers["Location"])
      origin, target = urlsplit(url), urlsplit(destination)
      response.close()
      if (origin.scheme, origin.netloc) != (target.scheme, target.netloc):
          raise ValueError("Redirect destination is not permitted")
      response = requests.get(destination, auth=auth, allow_redirects=False)

For POST or streamed uploads, handle method changes and replay of the body explicitly. Do not reuse stale digest or
signature headers from the first request.

Authors
-------
* `Andrey Kislyuk <https://kislyuk.com>`

Links
-----
* `Project home page (GitHub) <https://github.com/pyauth/requests-http-signature>`_
* `Package documentation <https://pyauth.github.io/requests-http-signature/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/requests-http-signature>`_
* `Change log <https://github.com/pyauth/requests-http-signature/blob/master/Changes.rst>`_
* `http-message-signatures <https://github.com/pyauth/http-message-signatures>`_ - implements HTTP message signing
  and verification
* `IETF RFC 9421, HTTP Message Signatures <https://datatracker.ietf.org/doc/rfc9421/>`_

Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/pyauth/requests-http-signature/issues>`_.

License
-------
Copyright 2017-2026, Andrey Kislyuk and requests-http-signature contributors. Licensed under the terms of the
`Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_. Distribution of attribution information,
LICENSE and NOTICE files with source copies of this package and derivative works is **REQUIRED** as specified by the
Apache License.

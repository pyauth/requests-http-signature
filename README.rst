requests-http-signature: A Requests auth module for HTTP Signature
==================================================================
**requests-http-signature** is a `Requests <https://github.com/requests/requests>`_ `authentication plugin
<http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass) implementing
the `IETF HTTP Message Signatures draft RFC <https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/>`_.

Installation
------------
::

    $ pip install requests-http-signature

Usage
-----

.. code-block:: python

  import requests
  from requests_http_signature import HTTPSignatureAuth, algorithms
  
  preshared_key_id = 'squirrel'
  preshared_secret = b'monorail_cat'
  url = 'http://example.com/path'

  auth = HTTPSignatureAuth(key=preshared_secret,
                           key_id=preshared_key_id,
                           signature_algorithm=algorithms.HMAC_SHA256)
  requests.get(url, auth=auth)

By default, only the ``Date`` header and the ``@method``, ``@authority``, and ``@target-uri`` derived component
identifiers are signed for body-less requests such as GET. The ``Date`` header is set if it is absent. In addition, for
requests with bodies (such as POST), the ``Content-Digest`` header is set to the SHA256 of the request body using the
format described in the
`IETF Digest Fields draft RFC <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers>`_ and signed.
To add other headers to the signature, pass an array of header names in the ``covered_component_ids`` keyword argument.
See the `API documentation <https://pyauth.github.io/requests-http-signature/#id1>`_ for the full list of options and
details.

Verifying responses
~~~~~~~~~~~~~~~~~~~
The class method ``HTTPSignatureAuth.verify()`` can be used to verify responses received back from the server:

.. code-block:: python

  class key_resolver:
      def resolve_public_key(self, key_id):
          assert key_id == 'squirrel'
          return 'monorail_cat'

  response = requests.get(url, auth=auth)
  HTTPSignatureAuth.verify(response,
                           signature_algorithm=algorithms.HMAC_SHA256,
                           key_resolver=key_resolver)

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

   verify_result = HTTPSignatureAuth.verify(request, ...)

See the `API documentation <https://pyauth.github.io/requests-http-signature/#id1>`_ for full details.

Asymmetric key algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~
To sign or verify messages with an asymmetric key algorithm, set the ``signature_algorithm`` keyword argument to
``algorithms.ED25519``, ``algorithms.ECDSA_P256_SHA256``, ``algorithms.RSA_V1_5_SHA256``, or
``algorithms.RSA_PSS_SHA512``. Note that signing with rsa-pss-sha512 is not currently supported due to a limitation of
the cryptography library.

For asymmetric key algorithms, you can supply the private key as the ``key`` parameter to the ``HTTPSignatureAuth()``
constructor as bytes in the PEM format, or configure the key resolver as follows:

.. code-block:: python

  with open('key.pem', 'rb') as fh:
      auth = HTTPSignatureAuth(algorithm=algorithms.RSA_V1_5_SHA256,
                               key=fh.read(),
                               key_id=preshared_key_id)
  requests.get(url, auth=auth)

  class MyKeyResolver:
      def resolve_public_key(self, key_id: str):
          return public_key_pem_bytes[key_id]

      def resolve_private_key(self, key_id: str):
          return private_key_pem_bytes[key_id]

  auth = HTTPSignatureAuth(algorithm=algorithms.RSA_V1_5_SHA256,
                           key=fh.read(),
                           key_resolver=MyKeyResolver())
  requests.get(url, auth=auth)

Digest algorithms
~~~~~~~~~~~~~~~~~
If you need to generate a Content-Digest header using SHA-512, you can do so via subclassing::

  class MySigner(HTTPSignatureAuth):
      def add_digest(self, request):
          super().add_digest(request, algorithm="sha-512")

Links
-----
* `Project home page (GitHub) <https://github.com/pyauth/requests-http-signature>`_
* `Package documentation <https://pyauth.github.io/requests-http-signature/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/requests-http-signature>`_
* `Change log <https://github.com/pyauth/requests-http-signature/blob/master/Changes.rst>`_
* `http-message-signatures <https://github.com/pyauth/http-message-signatures>`_ - a dependency of this library that
  handles much of the implementation
* `IETF HTTP Signatures draft <https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures>`_

Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/pyauth/requests-http-signature/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

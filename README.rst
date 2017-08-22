requests-http-signature: A Requests auth module for HTTP Signature
==================================================================

**requests-http-signature** is a `Requests <https://github.com/requests/requests>`_ `authentication plugin
<http://docs.python-requests.org/en/master/user/authentication/>`_ (``requests.auth.AuthBase`` subclass) implementing
the `IETF HTTP Signatures draft <https://tools.ietf.org/html/draft-cavage-http-signatures>`_. It has no dependencies
outside the standard library.

.. code-block:: python

  import requests
  from requests_http_signature import HTTPSignatureAuth
  preshared_secret = 'monorail_cat'
  url = 'http://httpbin.org/get'
  requests.get(url, auth=HTTPSignatureAuth(secret=preshared_secret))


Installation
------------
::

    pip install requests-http-signature

Links
-----
* `IETF HTTP Signatures draft <https://tools.ietf.org/html/draft-cavage-http-signatures>`_
* `Project home page (GitHub) <https://github.com/kislyuk/requests-http-signature>`_
* `Documentation (Read the Docs) <https://requests-http-signature.readthedocs.io/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/requests-http-signature>`_
* `Change log <https://github.com/kislyuk/requests-http-signature/blob/master/Changes.rst>`_

Bugs
~~~~
Please report bugs, issues, feature requests, etc. on `GitHub <https://github.com/kislyuk/requests-http-signature/issues>`_.

License
-------
Licensed under the terms of the `Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_.

.. image:: https://travis-ci.org/kislyuk/requests-http-signature.png
        :target: https://travis-ci.org/kislyuk/requests-http-signature
.. image:: https://codecov.io/github/kislyuk/requests-http-signature/coverage.svg?branch=master
        :target: https://codecov.io/github/kislyuk/requests-http-signature?branch=master
.. image:: https://img.shields.io/pypi/v/requests-http-signature.svg
        :target: https://pypi.python.org/pypi/requests-http-signature
.. image:: https://img.shields.io/pypi/l/requests-http-signature.svg
        :target: https://pypi.python.org/pypi/requests-http-signature
.. image:: https://readthedocs.org/projects/requests-http-signature/badge/?version=latest
        :target: https://requests-http-signature.readthedocs.org/

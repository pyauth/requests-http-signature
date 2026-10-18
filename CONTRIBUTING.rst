Development and releases
========================

Development
-----------
Use Python 3.10 or newer. Install the package and development dependencies in a virtual environment::

    python -m pip install --upgrade pip
    python -m pip install -e '.[tests,docs]'
    make test
    python -m build

``make test`` runs Ruff lint and formatting checks, Mypy, and the unit tests. Without Make, run::

    python -m ruff check .
    python -m ruff format --check .
    python -m mypy requests_http_signature
    python test/test.py -v

Build the documentation with ``python -m sphinx -W --keep-going docs docs/html``.

Versioning
----------
Like ``http-message-signatures``, this package uses Hatch with ``hatch-vcs``, which obtains versions from Git tags
through setuptools-scm. Release tags have the form ``vMAJOR.MINOR.PATCH``. There is no version file to edit.
Checkouts used for builds must include Git history and tags; source distributions contain the version metadata
needed to build wheels without Git.

Publishing setup
----------------
Configure the following GitHub trusted publisher for the ``requests-http-signature`` project on PyPI:

* Owner: ``pyauth``
* Repository: ``requests-http-signature``
* Workflow: ``release.yml``
* Environment: ``release``

Create the matching ``release`` environment in the GitHub repository and allow release tags to deploy to it.
Publishing uses GitHub's OpenID Connect token; no PyPI API token or local Twine upload is needed.

For documentation, select **GitHub Actions** as the repository's GitHub Pages publishing source and allow release
tags to deploy to the ``github-pages`` environment. The documentation workflow builds on pushes and pull requests,
and deploys on version tags or manual dispatch.

Releasing
---------
From a clean checkout with an upstream branch, run ``make release-patch``, ``make release-minor``, or
``make release-major``. These helpers require Bash, Make, Perl, Pandoc, moreutils, and the GitHub CLI. They prompt
for release notes, update the changelog, create an annotated version tag, push the commit and tag, and create a
GitHub release with a wheel attached.

The tag push starts ``release.yml``, which runs checks, builds the source distribution and wheel, and publishes
them to PyPI using trusted publishing. Documentation is built and deployed by ``docs.yml``.

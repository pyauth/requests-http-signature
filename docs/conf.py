import os
import sys
from importlib.metadata import version as distribution_version

sys.path.insert(0, os.path.abspath(".."))

project = "requests-http-signature"
copyright = "Andrey Kislyuk"
author = "Andrey Kislyuk"
release = distribution_version(project)
version = release
language = "en"
master_doc = "index"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
autodoc_typehints = "description"

html_theme = "furo"

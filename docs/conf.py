project = "requests-http-signature"
copyright = "Andrey Kislyuk"
author = "Andrey Kislyuk"
version = ""
release = ""
language = "en"
master_doc = "index"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode", "sphinx_copybutton"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "html", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
autodoc_typehints = "description"
autodoc_member_order = "bysource"
autoclass_content = "both"

templates_path = [""]
html_theme = "furo"
html_sidebars = {
    "**": [
        "sidebar/brand.html",
        "sidebar/search.html",
        "sidebar/scroll-start.html",
        "toc.html",
        "sidebar/scroll-end.html",
    ]
}

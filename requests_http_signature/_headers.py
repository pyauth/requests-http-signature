"""Preserve HTTP field lines before constructing signature components."""

from typing import Any

import requests
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from urllib3.response import HTTPResponse


def header_values(message: Any) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for name, value in message.headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise HTTPMessageSignaturesException("Header names and values must be strings")
        fields.setdefault(name.lower(), []).append(value)

    if isinstance(message, requests.Response) and isinstance(message.raw, HTTPResponse):
        # Requests combines response field lines in response.headers. Recover
        # their boundaries from urllib3, but never ignore edits to the public view.
        raw_fields: dict[str, list[str]] = {}
        for name, value in message.raw.headers.items():
            raw_fields.setdefault(name.lower(), []).append(value)
        for name, values in raw_fields.items():
            if len(values) > 1:
                if name not in fields or ", ".join(fields[name]) != ", ".join(values):
                    raise HTTPMessageSignaturesException(f"Response header {name!r} differs from its raw field lines")
                fields[name] = values
    return fields

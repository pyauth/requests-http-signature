"""Preserve HTTP field lines before constructing signature components."""

from copy import copy
from typing import Any

import requests
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from http_message_signatures.structures import normalize_header_value
from urllib3.response import HTTPResponse


def header_values(message: Any) -> dict[str, list[str]]:
    if isinstance(message.headers, SignatureHeaders):
        return message.headers.field_values
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


class SignatureHeaders(requests.structures.CaseInsensitiveDict):
    """Per-operation header view with both field lines and linear-time joins.

    Only used on private snapshots. The underlying signature library sees one
    value per name, while our resolver retains the original field boundaries.
    """

    def __init__(self, fields: dict[str, list[str]]) -> None:
        self.field_values = fields
        super().__init__(
            (name, ", ".join(normalize_header_value(v) for v in values)) for name, values in fields.items()
        )


def message_snapshot(message: Any) -> Any:
    if isinstance(message, requests.Response):
        # Response.__getstate__, invoked by copy.copy, reads response.content.
        # Copy its stored attributes without invoking that serialization hook.
        result = requests.Response()
        result.__dict__.update(message.__dict__)
    else:
        result = copy(message)
    result.headers = SignatureHeaders(header_values(message))
    if isinstance(message, requests.Response) and message.request is not None:
        result.request = message_snapshot(message.request)
    return result


def check_message_size(
    message: Any, *, max_header_bytes: int, max_header_count: int, max_signature_field_bytes: int, max_url_length: int
) -> None:
    """Bound input before normalization/parsing, without inspecting its syntax."""
    header_sources = [message.headers]
    if isinstance(message, requests.Response) and isinstance(message.raw, HTTPResponse):
        header_sources.append(message.raw.headers)
    for headers in header_sources:
        total = 0
        signature_sizes: dict[str, int] = {}
        for count, (name, value) in enumerate(headers.items(), start=1):
            if not isinstance(name, str) or not isinstance(value, str):
                raise HTTPMessageSignaturesException("Header names and values must be strings")
            total += len(name) + len(value) + 4
            if count > max_header_count or total > max_header_bytes:
                raise HTTPMessageSignaturesException("Message headers exceed verification size limits")
            name = name.lower()
            if name in {"signature", "signature-input"}:
                signature_sizes[name] = (
                    signature_sizes.get(name, 0) + len(value) + (2 if name in signature_sizes else 0)
                )
                if signature_sizes[name] > max_signature_field_bytes:
                    raise HTTPMessageSignaturesException("Signature field exceeds verification size limit")
    request = message.request if isinstance(message, requests.Response) else message
    if request is not None and request.url is not None and len(request.url) > max_url_length:
        raise HTTPMessageSignaturesException("Request URL exceeds verification size limit")
    if isinstance(message, requests.Response) and request is not None:
        check_message_size(
            request,
            max_header_bytes=max_header_bytes,
            max_header_count=max_header_count,
            max_signature_field_bytes=max_signature_field_bytes,
            max_url_length=max_url_length,
        )

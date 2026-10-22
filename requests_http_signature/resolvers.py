"""Requests-aware signature components, including RFC 9421 binary wrapping."""

from typing import Any

import http_sf
from http_message_signatures import HTTPSignatureComponentResolver as BaseComponentResolver
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from http_message_signatures.structures import normalize_header_value
from http_sf.compat import Item
from http_sf.types import ListType

from ._headers import header_values


class HTTPSignatureComponentResolver(BaseComponentResolver):
    """Resolve ``bs`` components from separate field lines, including raw responses.

    Header strings use Requests' Latin-1 mapping of HTTP field octets. ``bs``
    may be combined with ``req``, but not ``sf``, ``key``, or trailers.
    """

    def __init__(self, message: Any) -> None:
        super().__init__(message)
        self.field_values = header_values(message)

    def resolve(self, component_node: Item) -> str:
        name = str(component_node.value)
        params = component_node.params
        if "req" in params:
            # The parent validates req and dispatches to this resolver class
            # with the associated request and the remaining parameters.
            return super().resolve(component_node)
        if "bs" not in params:
            if name == "set-cookie" and len(self.field_values.get(name, ())) > 1:
                raise HTTPMessageSignaturesException("Multiple Set-Cookie field values require the bs parameter")
            return super().resolve(component_node)
        if params["bs"] is not True or name.startswith("@") or set(params) != {"bs"}:
            raise HTTPMessageSignaturesException("bs must be a Boolean flag on a field, without sf, key, or tr")
        if name not in self.field_values:
            raise HTTPMessageSignaturesException(f"Covered header field {name!r} not found in the message")
        values: ListType = []
        for value in self.field_values[name]:
            value = normalize_header_value(value)
            if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
                raise HTTPMessageSignaturesException("Binary wrapping cannot hide invalid HTTP field controls")
            try:
                values.append(value.encode("latin-1"))
            except UnicodeEncodeError as e:
                raise HTTPMessageSignaturesException("Header values must represent HTTP octets using Latin-1") from e
        return http_sf.ser(values)

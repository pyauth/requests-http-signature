"""Requests-aware signature components, including RFC 9421 binary wrapping."""

from typing import Any
from urllib.parse import parse_qs, quote, unquote

import http_sf
from http_message_signatures import HTTPSignatureComponentResolver as BaseComponentResolver
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from http_message_signatures.structures import normalize_header_value
from http_sf.compat import Dictionary, Item
from http_sf.types import ListType

from ._headers import header_values, message_snapshot


class HTTPSignatureComponentResolver(BaseComponentResolver):
    """Resolve ``bs`` components from separate field lines, including raw responses.

    Header strings use Requests' Latin-1 mapping of HTTP field octets. ``bs``
    may be combined with ``req``, but not ``sf``, ``key``, or trailers.
    """

    def __init__(self, message: Any) -> None:
        # The dependency joins repeated field values by repeated concatenation.
        # Give it a view combined once, retaining field lines for bs resolution.
        super().__init__(message_snapshot(message))
        self.message = message
        self.field_values = header_values(message)
        self._request_resolver: HTTPSignatureComponentResolver | None = None
        self._dictionaries: dict[str, Dictionary] = {}
        self._query: dict[str, list[str]] | None = None

    def resolve(self, component_node: Item) -> str:
        name = str(component_node.value)
        params = component_node.params
        if "req" in params:
            if params["req"] is not True or self.message_type != "response":
                return super().resolve(component_node)
            if self._request_resolver is None:
                self._request_resolver = self.__class__(self.message.request)
            request_node = Item(component_node.value)
            request_node.params.update((key, value) for key, value in params.items() if key != "req")
            return self._request_resolver.resolve(request_node)
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

    def get_dictionary_member(self, component_id: str, field_value: str, params: dict) -> str:
        if set(params) - {"key", "sf"} or ("sf" in params and params["sf"] is not True):
            raise HTTPMessageSignaturesException("Dictionary member coverage only supports key and the sf flag")
        key = params["key"]
        if not isinstance(key, str):
            raise HTTPMessageSignaturesException("The key parameter must be a string")
        if component_id not in self._dictionaries:
            dictionary = Dictionary()
            try:
                dictionary.parse(field_value.encode())
            except (ValueError, TypeError) as e:
                raise HTTPMessageSignaturesException(f"Covered field {component_id!r} is not a Dictionary") from e
            self._dictionaries[component_id] = dictionary
        if key not in self._dictionaries[component_id]:
            raise HTTPMessageSignaturesException(f"Covered field {component_id!r} has no member {key!r}")
        return str(self._dictionaries[component_id][key])

    def get_query_params(self, *, name: str) -> str:
        if not isinstance(name, str):
            raise HTTPMessageSignaturesException("The query parameter name must be a string")
        if self._query is None:
            self._query = parse_qs(self.url_parts.query or "", keep_blank_values=True)
        name = unquote(name)
        if name not in self._query:
            raise HTTPMessageSignaturesException(f"Query parameter {name!r} not found in the message URL")
        if len(self._query[name]) != 1:
            raise HTTPMessageSignaturesException("Query parameters with multiple values are not supported.")
        return quote(self._query[name][0], safe="*").replace("~", "%7E")

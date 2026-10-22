"""Signature selection and repeated Set-Cookie policy for Requests messages."""

from collections.abc import Sequence
from typing import Any

from http_message_signatures import HTTPMessageSigner as BaseMessageSigner
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureAlgorithm,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    PreparedSignature,
)
from http_message_signatures.exceptions import HTTPMessageSignaturesException

from ._headers import header_values
from .resolvers import HTTPSignatureComponentResolver


class SingleSignatureVerifier(HTTPMessageVerifier):
    """Enforce this package's single-signature policy before key resolution."""

    def _get_sig_inputs_and_signatures(self, message: Any, **kwargs: Any) -> Any:
        selected = list(super()._get_sig_inputs_and_signatures(message, **kwargs))
        if len(selected) != 1:
            raise InvalidSignature("Select a single signature using expect_tag and expect_label")
        return iter(selected)


class HTTPMessageSigner(BaseMessageSigner):
    """Sign requests/responses, automatically covering repeated Set-Cookie with bs.

    The remaining API is inherited from ``http_message_signatures.HTTPMessageSigner``.
    As with that API, response signing requires an explicit coverage profile and
    does not generate a body digest.
    """

    def __init__(
        self,
        *,
        signature_algorithm: type[HTTPSignatureAlgorithm],
        key_resolver: HTTPSignatureKeyResolver | None = None,
        component_resolver_class: type = HTTPSignatureComponentResolver,
    ) -> None:
        super().__init__(
            signature_algorithm=signature_algorithm,
            key_resolver=key_resolver,
            component_resolver_class=component_resolver_class,
        )

    def prepare(
        self,
        message: Any,
        *,
        covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
        **kwargs: Any,
    ) -> PreparedSignature:
        if len(header_values(message).get("set-cookie", ())) > 1:
            components = self._parse_covered_component_ids(covered_component_ids)
            found = False
            for node in components:
                if node.value == "set-cookie" and "req" not in node.params:
                    if node.params.get("bs", True) is not True or set(node.params) - {"bs"}:
                        raise HTTPMessageSignaturesException("Repeated Set-Cookie requires bs without other parameters")
                    node.params["bs"] = True
                    found = True
            if not found:
                components.extend(self._parse_covered_component_ids(('"set-cookie";bs',)))
            covered_component_ids = [str(node) for node in components]
        return super().prepare(message, covered_component_ids=covered_component_ids, **kwargs)

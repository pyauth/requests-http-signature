Verification complexity review
==============================

Scope
-----
This review covers the work done by ``HTTPSignatureAuth.verify()`` on untrusted message metadata before a signature
is authenticated, and avoidable work before body-digest validation. The dependency implementations inspected were
http-message-signatures 2.1.0 and http-sf 1.4.0. Requests response handling was exercised with Requests 2.34.2 and
urllib3 2.8.0. This is a targeted review, not a proof of a total CPU or memory bound for the application.

Findings and implemented changes
------------------------------------------------

* **Unbounded metadata.** Signature dictionaries, headers, and URLs previously reached normalization and parsing
  without package-level size limits. Verification now rejects more than 64 KiB of header text, 100 field lines,
  16 KiB per combined signature field, or an 8192-character request URL before those operations. Response raw
  headers and associated request metadata are included. These defaults are configurable class attributes;
  larger application profiles must opt in. The checks count lengths only and do not inspect syntax.

* **Quadratic repeated-header concatenation.** The dependency's ``get_header_fields()`` repeatedly appends to an
  immutable string stored in a dictionary. For many similarly sized values of one field, this copies increasingly
  long prefixes. Private message snapshots now normalize each field line and join each group once. Original
  field boundaries remain available for ``bs``. Requests response snapshots copy stored attributes without
  invoking ``Response.__getstate__``, which otherwise reads the response body.

* **Repeated parsing across components.** Each dictionary-member selection previously reparsed the whole field,
  each query-parameter selection reparsed the query, and each ``req`` component constructed another resolver.
  A resolver now caches parsed dictionaries and the query, and shares one associated request resolver. For a
  field or query of size N with K selected members, the repeated parsing cost falls from O(KN) to O(N), plus
  the cost of selecting and serializing the requested values. Caches live only within an operation.

* **Multiple cryptographic verifications before rejection.** Selecting a tag shared by several signatures could
  verify them all before the wrapper rejected the result for containing more than one signature. The default
  verifier now checks that selection leaves one candidate before any key resolution or cryptographic work.
  It uses the dependency's existing signature-dictionary parsing and selection logic.

* **Body reads before authentication.** Verification previously obtained response content before checking the
  signature. It now verifies the signature and known coverage requirements first. Missing, malformed, invalid,
  or ambiguously selected signatures cannot cause an automatic body read. Content-Digest members and digest
  lengths are all validated before hashing a supplied body, avoiding hashing when a later member is invalid.

The existing http-sf parser advances a cursor and handles Structured Field syntax; no replacement parser,
tokenizer, or syntax pre-scan was introduced. The dependency's unfolding regular expression already guards
against restarting at every position of a whitespace run. No additional regular-expression complexity defect
was established by this review. URL and Structured Field input limits provide a bound on input to those parsers.

Validation
----------
Regression tests instrument parser, key-resolver, query-parser, and body-reader calls. They check that oversized
metadata is rejected before parsing or key lookup, split signature fields share a size budget, ambiguous selection
does not resolve keys, missing coverage does not read a response, and dictionary/query parsing happens once per
verification. Tests also cover raw response headers, associated requests, configurable limits, cache freshness,
and invalid digest members failing before hashing. Existing signature, response, and binary-wrapping tests remain
part of the suite.

A local Python 3.12 timing check using repeated 128-character field values measured the dependency's combining
helper at 2.35, 5.18, 13.58, and 33.01 ms for 500, 1000, 2000, and 4000 values. The single-join implementation took
1.84, 3.66, 7.34, and 14.19 ms. These are illustrative measurements, not performance guarantees or timing-based tests;
the larger inputs exceed the default verification limits. The regression suite checks behavior and operation counts.

Remaining application responsibilities
------------------------------------------------
Size limits apply at the verification boundary, after Requests or a server has received and represented headers.
They cannot undo earlier network, HTTP-parser, or cookie-jar work. Callers still need network timeouts, request
rate limits, bounded key lookup, and body-size limits. Requests must use ``stream=True`` to defer downloads.
Automatic body reads happen only after the signature passes, but a valid signature does not cap the subsequent
body; callers needing a hard bound should capture bounded bytes and supply ``body=``. Signature-base serialization
still costs time and memory proportional to the covered values. Raising metadata limits also raises the possible
cost of invalid messages. Custom resolvers and replacement verifier classes must preserve these protections.

Source references
-----------------
* `RFC 9421, field binary wrapping <https://www.rfc-editor.org/rfc/rfc9421.html#section-2.1.3>`_ and
  `Set-Cookie field handling <https://www.rfc-editor.org/rfc/rfc9421.html#section-7.5.6>`_.
* `http-message-signatures 2.1.0 implementation
  <https://github.com/pyauth/http-message-signatures/tree/v2.1.0/http_message_signatures>`_.
* `http-sf project and parser <https://github.com/mnot/http-sf>`_.

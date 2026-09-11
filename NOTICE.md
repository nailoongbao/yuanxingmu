Agent Defense Check's original code is licensed under the MIT License in
LICENSE. This distribution also contains an adapted rule template under
Apache-2.0, as described below. The package license expression
"MIT AND Apache-2.0" records the licenses of these included components;
it does not offer a choice of licenses for the upstream material.

The email-policy rule template is adapted from the Invariant project's
README at commit 2340fe2d9cd619f73d5b67fa05bf8a08c7cad515:
https://github.com/invariantlabs-ai/invariant/blob/2340fe2d9cd619f73d5b67fa05bf8a08c7cad515/README.md

Copyright 2025 Invariant Labs AG

The upstream material is licensed under the Apache License, Version 2.0.
The complete upstream LICENSE, including its copyright notice, is preserved
without alteration in LICENSES/Invariant-Apache-2.0.txt. Its exact source is:
https://raw.githubusercontent.com/invariantlabs-ai/invariant/2340fe2d9cd619f73d5b67fa05bf8a08c7cad515/LICENSE

The adapted rule text is constructed by email_policy() in
defensecheck/policy.py and is stored as the reference rule in
tests/fixtures/invariant-fixed.policy. Rendered copies also appear in the
bundled demo evidence. The rule was modified to check a case-insensitive,
exact allowed email domain, to bind the sending ToolCall explicitly before
testing the disallowed recipient, and to support configurable tool names
and an allowed domain. These adapted rule portions retain their upstream
Apache-2.0 licensing. The surrounding Python validation and rendering code
is original project code under MIT.

The gateway and aggregation runtimes are installed as separate dependencies;
their distributions are not vendored in this repository. They retain their
own licenses. The runtime launcher uses FastMCP's public create_proxy API.

Research provenance for the corrected policy is in tests/fixtures. The
runtime demo independently exercises the policy using the actual engine.

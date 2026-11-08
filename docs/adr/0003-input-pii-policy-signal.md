# ADR 0003: Personal data in requests as a policy signal

- Status: accepted
- Date: 2026-11-08
- Task: RF-474e756a
- Supersedes: the input-side PII part of
  [ADR 0002](0002-no-input-pii-toxicity-topic.md) (decision 1). The toxicity
  and topic part of ADR 0002 stands.

## Context

[ADR 0002](0002-no-input-pii-toxicity-topic.md) decided not to build
input-side PII detection for now, and named the conditions under which it
would be built: a new field (not `pii.entities`) that reports the kinds found
in request text; `log` first, no redaction; the output guard's detectors
exported and shared, not copied; a per-org switch, off by default. It also
named the risks: stored rules that name `pii.entities` would start to match,
and "PII detection" would overstate what five regular expressions find.

An owner now has a concrete need: log, and for some projects block, requests
that carry card numbers, citizen IDs or contact data, for example before they
reach an upstream that should not receive them. This ADR records how the
feature meets each condition of ADR 0002.

## Decision

1. **Shared detectors.** `outputguard.CountPII(text)` runs the output guard's
   own personal-data matcher (`inlineMatches`, with e-mail, phone, card, CCCD
   and IPv4 on) on a string and returns a count per kind, never a value. The
   output guard's code path is not changed: its golden tests and benchmarks
   are the same.
2. **New fields, not `pii.entities`.** Rules get `input.pii.kinds` (list of
   `email`, `phone`, `card`, `cccd`, `ipv4`, in that order, each kind found
   at least once) and `input.pii.count` (int, all values of all kinds).
   `pii.entities` stays removed: new rules may not name it, and a stored rule
   that does still reads `[]` whatever the request holds, so it matches
   exactly as before (tested in `internal/policy` and through the gateway).
3. **Per-org switch, off by default.** `input_pii` in the org's guard
   settings (`organizations.guard_settings`, a JSON object; no migration is
   needed). Unset or `false`: no text is checked, and the fields read `[]`
   and `0`. There is no gateway-wide setting, so the check never runs for an
   org that did not turn it on. Guard settings are read per request, so a
   change applies to the next request.
4. **Which text.** The text the injection scan collects for the request, of
   three sources: user turns (all parts, the legacy prompt and suffix,
   Responses prompt variables), tool results (and web search or fetch
   results, Responses tool output items), and documents (Messages API
   `document` and `search_result` blocks). It is the cleaned text, after the
   sanitizer. This is the same on chat completions, `/v1/messages` and
   `/v1/responses`, streamed or not. A source that `SCAN_ROLES` (or the org)
   does not scan is not checked either.
   - **System and developer prompts are left out**, also when they are
     scanned for injection. They are the operator's own text and often hold
     example addresses, phone numbers and hosts ("reply from
     support@example.com"); counting them would make every request of such
     an application match, and a rule on the count useless. The operator
     already knows what its prompts contain.
   - Tool-call arguments in the history (the model's own output) and tool
     descriptions are left out for the same reason: they are not data the
     user or a third party sent.
   - Earlier turns count too, also on `/v1/messages` with
     `SCAN_HISTORY=latest`, where their user text is not classified again:
     they go upstream with every request, and the check needs no model call.
5. **Actions.** Rules can `log` or `block` on the fields (and `allow` or
   `route`, like any rule). There is no `redact`: the policy engine still
   refuses it and the gateway never rewrites a request for personal data.
   Redaction stays out of scope for the reasons ADR 0002 gives.
6. **Records.** The audit row's `pii_entities` column gets
   `input:pii_<kind>=<n>` tags next to the output guard's `output:<kind>=<n>`;
   `detection.blocked` and `detection.flagged` events get `pii_kinds` and
   `pii_count`, which alert rules can use. Values are never stored, logged
   or sent.
7. **Honest naming.** The admin UI calls the switch "Detect personal data in
   requests" and says, next to it, which five kinds are checked and that
   names, street addresses, bank account numbers and foreign ID numbers are
   not. The field help says the same.

## Coverage and known behaviour

- `email`: addresses with a dot in the domain.
- `phone`: Vietnamese numbers, `+84`, `84` or `0` followed by a mobile or
  landline prefix and seven more digits, with optional spaces, dots or
  dashes. Other countries' numbers are not found.
- `card`: 13 to 19 digits, in groups, that pass the Luhn check. About one in
  ten random 13 to 19 digit numbers passes Luhn, so a long order or tracking
  number can count as a card.
- `cccd`: 12 digits starting with 0 (Vietnamese citizen ID).
- `ipv4`: four dotted numbers of at most 255 each. A version number such as
  `1.2.3.4` counts as an IPv4 address (a longer dotted run such as an OID
  does not). Rules that should not act on addresses can test the other
  kinds, for example `"card" in input.pii.kinds`.
- Order numbers, ISO timestamps, Unix times, amounts and three-part versions
  are not counted (tests in `internal/outputguard/pii_test.go`).

## Cost

Measured on an Apple M3 Max (`BenchmarkInputPII` in `cmd/gateway`,
`BenchmarkCountPII` in `internal/outputguard`), with a request whose user
text ends with an e-mail address and a phone number:

| Request text | Sanitize step, switch off | Switch on | Added |
| --- | --- | --- | --- |
| 2 KB | 148 µs | 159 µs | about 11 µs |
| 20 KB | 1.62 ms | 1.68 ms | about 57 µs |

The whole HTTP path with L1 (p50) goes from 1.18 ms to 1.20 ms for 2 KB and
from 11.08 ms to 11.19 ms for 20 KB. Text without digits or `@` costs much
less (0.7 µs for 2 KB). With the switch off nothing runs: the detectors are
not called at all (`TestInputPIIOffCostsNothing`).

## Consequences

- ADR 0002's status says that its input-side PII decision is superseded by
  this ADR; its toxicity and topic decision is unchanged.
- README and README.vi list the new fields; ROADMAP no longer lists input PII
  under "Later"; CHANGELOG has the feature under "Added".
- Redaction of personal data in requests is still not built. If it is, it
  needs the `redact` action, reversible placeholders and a new ADR.

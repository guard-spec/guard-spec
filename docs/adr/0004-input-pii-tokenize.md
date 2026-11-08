# ADR 0004: Keeping personal data in requests from the model provider

- Status: accepted
- Date: 2026-11-08
- Task: RF-5b9b3aa2
- Builds on: [ADR 0003](0003-input-pii-policy-signal.md), which counts
  personal data in requests for rules and left redaction to a later ADR.

## Context

ADR 0003 gives rules `input.pii.kinds` and `input.pii.count`, but a request
that is not blocked still reaches the model provider with the personal data
in it. Banks, health care and public bodies in Vietnam often may not send
CCCD numbers, card numbers or phone numbers to a third party (Decree
13/2023), and blocking the request is no answer for an assistant that has to
read them.

## Decision

1. **An organization setting, not a policy action.** `input_pii_action` in
   the guard settings: `off` (default), `redact` or `tokenize`, with
   `input_pii_kinds` to limit it to some kinds. Rules keep deciding whether a
   request is allowed; the setting decides what an allowed request carries.
   A policy `redact` action would have to be defined for every rule field;
   the setting covers what the detectors find, which is what can be replaced.
2. **Tokenize is reversible inside the request only.** Each value becomes
   `⟦<KIND>_<n>⟧`, the same value the same token. The map lives in memory for
   the request and is never stored or logged. The answer gets the values back
   in the output guard's stream (`Scanner.WithTokens`), before its own checks,
   so the three APIs, streamed or not, are covered by the code that already
   handles text split across deltas; a guard that only restores is used when
   the output guard is off. `⟦` and `⟧` are rare in text and survive
   tokenizers; spaces and case inside a token are tolerated.
3. **What is replaced.** User turns, tool results and documents, after they
   are classified (detection and rules see the request as the client sent
   it), and the model's earlier turns the client sends back: with `tokenize`
   the client received the values in those answers. Tool-call arguments are
   rewritten as JSON (string values only). Left alone: system and developer
   prompts (the operator's text), signed thinking and reasoning (the provider
   checks the signature), and the provider's own server tool results (it made
   them). This is the same text ADR 0003 counts, plus the model's turns.
4. **Restored values are output like any other.** With `OUTPUT_REDACT_PII`
   the answer shows the redaction. A model that puts a token into a link or a
   tool call gets the value there: the same as without tokenization, where
   it saw the value itself; the output guard's link allowlist still applies.

## Consequences

- The detectors' limits are the feature's limits: names, street addresses,
  bank account numbers and foreign formats go upstream unchanged. The UI and
  docs say so.
- A model that changes a token beyond spaces and case (translates it, splits
  it) leaves it unrestored; the client sees the token, never another value.
- The audit row records counts per kind (`input:pii_tokenized_<kind>=<n>`,
  `input:pii_redacted_<kind>=<n>`), never values.
- ADR 0003's last consequence is resolved by this ADR.

# ADR 0002: No input-side PII, toxicity or topic detection for now

- Status: accepted; decision 1 (input-side PII) superseded by
  [ADR 0003](0003-input-pii-policy-signal.md) on 2026-11-08
- Date: 2026-11-06
- Task: RF-840422a3

> **Superseded in part.** Personal data in requests is now a policy signal,
> built on the conditions of decision 1 below: new fields `input.pii.kinds`
> and `input.pii.count`, a per-org switch off by default, `log` or `block`
> only, the output guard's detectors shared. See
> [ADR 0003](0003-input-pii-policy-signal.md). Decisions 2 and 3 (toxicity,
> topic, removed fields) stand.

## Context

An early design draft described three more detectors on the request side: PII
named-entity recognition, a toxicity classifier and a topic classifier, with
the policy fields `pii.entities`, `toxicity.score` and `topic.categories`.
None of them was ever built. What exists today:

- **Output guard PII redaction** (`internal/outputguard`). On responses, and on
  streams with a 256-character window, it redacts e-mail addresses,
  Vietnamese phone numbers, CCCD numbers, card numbers that pass the Luhn
  check and, optionally, IPv4 addresses (`OUTPUT_PII_REDACT`,
  `OUTPUT_PII_IPV4`). These are regular expressions with boundary checks. They
  are not NER: names, street addresses, bank account numbers and similar data
  are not found.
- **Removed policy fields.** `pii.entities`, `toxicity.score` and
  `topic.categories` were removed from the rule schema because no detector
  produced them. New rules may not name them. Rules stored before the removal
  still compile, and the fields keep the zero value they always had (`[]`, `0`),
  so these rules never match (`internal/policy/policy.go`, `removedFields`).
- **Placeholders in `inference.Runner`.** The runner still has PII, toxicity and
  topic slots that return a constant neutral score. `toxicity_score` is
  always 0 in the audit row and in `/guardrail/scan`.
- **The `redact` rule action** is refused by policy validation; the gateway
  never rewrites a request before forwarding it.

The question was whether to add PII detection to the input scan, for example by
reusing the output guard's detectors behind a policy switch, and what to do
about toxicity and topic detection.

## Options for input-side PII

1. **Reuse the output guard detectors on request text and expose the result to
   rules** (a list of kinds, such as `["email","card"]`), so an org can `log` or
   `block` requests that carry personal data.
2. **Redact personal data in the request** before it goes upstream.
3. **Do not build it now**, record why, and point users to what exists.

Option 1 is small on the detection side: the detectors in
`outputguard.inlineMatches` could be exported as a function over a string, and
the gateway already walks every user, tool and document part. The rest is not
small, and parts of it are risky:

- **Reusing `pii.entities` would change stored rules.** Rules saved before the
  field was removed evaluate it as `[]` today. If the field came back with
  values, those rules would start to match, possibly with `block`, without
  anyone editing them. A new signal needs a new field name, plus the schema,
  the admin UI rule editor, simulation, the audit row and docs.
- **The useful action is unclear.** People send their own personal data to a
  model on purpose ("write an e-mail to an@example.com", "check this card
  statement"). Blocking on its presence would refuse many legitimate
  requests. Logging it gives a count, not protection. The protective action is
  redaction, which is option 2.
- **Option 2 changes what the model sees.** Redacting a prompt changes the
  answer (the model can no longer write to the address it was given). Doing it
  well needs reversible placeholders and re-identification in the answer.
  That is a data-loss-prevention product, not a prompt-injection guard. It
  also means rewriting request bodies (string and part content, tool-call
  arguments, documents) and implementing the `redact` action, which the policy
  engine refuses today.
- **The coverage would be overstated.** Five regular expressions tuned for
  answers are not PII detection. Calling the input check "PII detection" would
  suggest names, addresses and account numbers are covered when they are not.

## Decision

1. **Input-side PII: not built for now (option 3).** The output guard stays the
   only place where personal data is handled. We will revisit when a user
   brings a concrete policy need. If we build it, it will be:
   a new field (not `pii.entities`) that reports kinds found in request text;
   `log` first, with no redaction; the output guard's detectors exported and
   shared, not copied; and a per-org switch, off by default.
2. **Toxicity and topic detection: not planned.** Guard Spec detects prompt
   injection and limits what a successful injection can do. Content
   moderation and topic control are a different problem:
   - They need their own multilingual classifiers and labelled data. We have
     no Vietnamese toxicity or topic data, and the eval set only covers
     injection.
   - Each extra model costs about as much as L2 per request. In our benchmark
     L2 adds about 1.8 ms to a short request and about 24 ms to a 2,000-character
     one on an Apple M3 Max (README, "Benchmarks").
   - Upstream providers and dedicated moderation models already do this, and
     the LLM-judge models that would do it best are not planned (ROADMAP,
     "Not planned").
3. The removed policy fields stay removed, and the placeholders in
   `inference.Runner` stay for now. They return neutral scores and cost almost
   nothing.

## What users can do instead

- **Personal data in answers**: keep `OUTPUT_PII_REDACT=true` (the default) and
  set `OUTPUT_PII_IPV4=true` if IPv4 addresses matter. The audit row counts
  what was redacted per kind, without content.
- **Personal data in prompts**: redact or tokenize it in your application, or in
  a DLP proxy before the gateway. The gateway forwards what it receives.
  `AUDIT_STORE_CONTENT=false` (the default) keeps prompt text out of the audit
  log, so the gateway itself stores only a hash and the length.
- **Rules**: CEL rules see detection signals (scores, categories, anomaly
  flags, model, size), never the request text, so a rule cannot match personal
  data or a topic. Use rules to block or log on injection signals, and to
  `route` a model or a project to an upstream you trust with the data (for
  example a self-hosted model).
- **Toxicity and topic**: use your upstream provider's moderation, or a
  moderation model in your application, before or after the call. Org
  exemplars (L3) make the gateway flag text similar to examples you give, but
  they are scored, blocked and audited as prompt injection. Do not use them as
  a topic filter.

## Consequences

- README lists input-side PII, toxicity and topic detection as decided against
  for now, with a link here, instead of "not built".
- ROADMAP lists input PII as a policy signal under "Later" with the conditions
  above, and toxicity and topic classifiers under "Not planned".
- No code changes: the policy schema, the gateway and the audit row stay as
  they are.

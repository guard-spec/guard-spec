# Roadmap

Plans, not promises. Priorities change with what users report. Items link to
issues once they exist.

## v0.2

Detection quality

- **Classifier v2: lower Vietnamese false positives.** With L2/L3 on, 7.0% of
  Vietnamese teencode and 3.8% of no-diacritics benign eval rows are blocked
  (README, "Benchmarks"). Target: Vietnamese benign FPR at or below 2% at the
  block threshold without losing recall. Needs more natural teencode and
  no-diacritics benign data, ideally reviewed by native speakers.
- **Publish the model weights on Hugging Face**, with the model card, the
  SHA-256 pinned in `models/manifest.yaml`, so `models-pull` fetches the
  classifier like the embedding model, without training it locally.

Product

- **Admin UI (N12).** Organizations, API keys, policies (rule builder over
  the existing JSON condition tree), guard settings, exemplars and the audit
  log, on top of the existing control-plane API.
- **Output guard: strip auto-linked URLs.** Many chat UIs turn a bare URL into
  a clickable link. The output guard removes markdown and HTML links to
  hosts off the allowlist, but leaves bare URLs without a query string; v0.2
  should treat bare URLs like links.
- **Audit columns for indirect sources.** Record which tool message, document
  or tool description gave the strongest indirect finding (source, index,
  category) in the audit row, not only the score and label.

Release and operations

- **A real amd64 benchmark.** All published numbers come from an Apple M3
  Max laptop. Measure the detector and end-to-end gateway latency on a
  typical x86-64 server CPU, L1 only and with L2/L3, and publish the method.
- **ONNX-enabled release images.** The GoReleaser images are static and run
  L1 only; publish a `-tags onnx` gateway image (built from
  `build/gateway.Dockerfile`) as part of the release, signed like the others.

## Later

- Per-organization output guard settings.
- A shared rate limiter (Redis or Postgres) so limits hold across replicas.
- More languages, starting with the ones users ask for.

## Not planned

Model routing, ClickHouse, GPU/Triton serving and LLM-judge models
(Qwen3Guard, Granite Guardian) appeared in an early design draft. They are not
planned for now; see [DESIGN.md](DESIGN.md).

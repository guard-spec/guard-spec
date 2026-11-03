# Contributing to Guard Spec

Thank you for helping. This file covers how to set up, test and submit a
change. Security problems go through [SECURITY.md](SECURITY.md), never a
public issue or pull request.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## The one rule about `eval/`

**`eval/` must never be used for tuning.** Do not train on it, calibrate on
it, pick thresholds, layer weights or epochs with it, or write rules by
reading its rows. It exists to measure, and every number we publish comes
from it. Use `train/data/val.jsonl`, `train/data/val_hard.jsonl` or your own
split for development, and run `eval/` once at the end.

The L1 rules were refined on half of `eval/` before this rule was written;
`eval/README.md` documents that, and the README marks L1 numbers as
optimistic. New rule changes must be developed on other data. A pull request
that changes detection should say which data it was developed on.

Training data must also drop every row whose fingerprint is in
`eval/fingerprints.txt` (see `eval/README.md`, "Leakage guard").

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
you wrote the change or have the right to submit it under the project's
license (Apache-2.0).

```bash
git commit -s -m "fix(sanitizer): strip U+2064 invisible plus"
# adds: Signed-off-by: Your Name <you@example.com>
```

Use your real name or a consistent public identity. To sign off commits you
already made: `git rebase --signoff main`.

## Development setup

You need Go (the version in `go.mod`), Docker with Compose v2, and for the
model layers a C toolchain (cgo). Python with [uv](https://docs.astral.sh/uv/)
is needed only to rebuild `eval/` or train the classifier.

```bash
git clone https://github.com/giaplee/guard-spec.git
cd guard-spec
go build ./...
docker compose up -d --build     # full stack with dev credentials, see README "Quick start"
```

Model layers (L2/L3):

```bash
make onnx-deps                   # libonnxruntime + libtokenizers.a into .onnx/, SHA-256 checked
go run ./cmd/models pull -dir models/cache    # multilingual-e5-small
# classifier: build with train/ or copy into models/local/guardspec-classifier-v1 (README "Models")
```

## Tests

```bash
go vet ./...
go test -race ./...                         # unit tests, no services needed
make test-onnx                              # -tags onnx; model tests skip without models/
make fuzz FUZZTIME=30s                      # sanitizer, policy and request fuzzers
```

Integration tests need Postgres with the migrations applied and the
application role's password set. The `integration` job in
`.github/workflows/ci.yml` is the reference setup:

```bash
export TEST_DATABASE_URL=postgres://guardspec_app:...@localhost:5432/guardspec?sslmode=disable
export TEST_OWNER_DATABASE_URL=postgres://ps:...@localhost:5432/guardspec?sslmode=disable
go test -race -tags integration ./...
```

A migration must have a working down step, also on a database with data in
it. CI applies all migrations, inserts rows, rolls everything back and
applies them again.

## Detector eval

```bash
go run ./cmd/eval -baseline eval/baseline.json        # L1, fails on a regression > 0.02
make eval-ml                                          # L1+L2+L3 vs eval/baseline-onnx.json (needs models)
go run ./cmd/eval -path tool                          # untrusted-content path
```

If a change moves the numbers on purpose, refresh the baseline in the same
pull request (`go test ./internal/evalset -run TestBaseline -update-baseline`)
and explain the change. Report numbers in the README only when you measured
them yourself, with the command, the hardware and the date.

## Pull requests

- Branch from `main`; keep a pull request to one topic.
- Commit messages follow Conventional Commits (`feat(gateway): ...`,
  `fix(outputguard): ...`, `docs: ...`).
- CI must pass: build, vet, tests (with `-race`), the onnx job, integration
  tests, golangci-lint, govulncheck, the license check and the GoReleaser
  config check.
- New dependencies must have a license that `make licenses-check` accepts.
  Do not add Llama, Gemma or other restricted model licenses.
- Update the README (and `README.vi.md` where it applies), `CHANGELOG.md` and
  `.env.example` when behaviour or configuration changes.
- Fill in the pull request template, including how you tested.

## Reporting false positives and false negatives

Use the "False positive / false negative" issue template. Remove personal and
confidential data from the text first. If the text cannot be shared, describe
its shape (language, variant, length, which layer scored it) instead.

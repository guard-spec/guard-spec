## What and why

<!-- What does this change, and why? Link the issue: Fixes #123 -->

## How it was tested

<!-- Commands you ran and what they showed: go test -race ./..., integration tests, cmd/eval, a curl against the stack. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md, DCO).
- [ ] `go vet ./...` and `go test -race ./...` pass.
- [ ] Detection changes: developed **without** `eval/`; `cmd/eval` run against the baseline, and the baseline refreshed with an explanation if numbers moved on purpose.
- [ ] Migrations: the down step works on a database with rows.
- [ ] Docs updated where behaviour or configuration changed (README, README.vi.md, .env.example, CHANGELOG.md).
- [ ] No secrets, personal data or model weights in the diff.

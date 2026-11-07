<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenSSF Best Practices badge: prepared answers

For the maintainer who registers the project. The
[OpenSSF Best Practices badge](https://www.bestpractices.dev/) is self-assessed
and needs a GitHub login of a maintainer, so it cannot be done from the
repository. This page holds the answers to the **passing** level, criterion by
criterion, with the evidence to paste into the "justification" fields.
OpenSSF Scorecard reads the badge level by the repository URL
(CII-Best-Practices check: in progress 2, passing 5, silver 7, gold 10).

Prepared on 2026-11-07 from `main` at v0.3.0. Re-check anything marked
**owner** before submitting: only a maintainer can confirm it.

## Steps

1. Sign in at <https://www.bestpractices.dev/en/projects/new> with GitHub
   (the account that maintains `guard-spec/guard-spec`).
2. Enter the repository URL `https://github.com/guard-spec/guard-spec`; the
   form fills the name, description, license and some criteria itself.
3. Go through the six sections (Basics, Change Control, Reporting, Quality,
   Security, Analysis) and set each criterion as in the tables below, pasting
   the justification. "N/A" is a valid answer where the table says so.
4. Save. With every MUST met and every SHOULD answered, the badge is
   "passing". Note the project number (`/projects/<id>`).
5. Add the badge to the badge rows of `README.md` and `README.vi.md`:
   `[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<id>/badge)](https://www.bestpractices.dev/projects/<id>)`.
   Scorecard picks it up on its next run (weekly, or the next push to `main`).

Links are full URLs so they can be pasted into the form as they are.

## Basics

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `description_good` | Met | README, first paragraph: a self-hosted gateway between an application and an LLM API that blocks prompt injection and checks the answers. https://github.com/guard-spec/guard-spec/blob/main/README.md |
| `interact` | Met | How to get (README "Quick start", "Install from a release"), give feedback (issue forms), contribute (CONTRIBUTING.md). https://github.com/guard-spec/guard-spec/blob/main/README.md |
| `contribution` | Met | https://github.com/guard-spec/guard-spec/blob/main/CONTRIBUTING.md (setup, tests, pull requests, DCO) |
| `contribution_requirements` | Met | Requirements in the "Pull requests" section, https://github.com/guard-spec/guard-spec/blob/main/CONTRIBUTING.md#pull-requests : Conventional Commits, DCO sign-off, CI green, tests, licenses |
| `floss_license` | Met | Apache-2.0. https://github.com/guard-spec/guard-spec/blob/main/LICENSE |
| `floss_license_osi` | Met | Apache-2.0 is OSI-approved |
| `license_location` | Met | https://github.com/guard-spec/guard-spec/blob/main/LICENSE at the repository root |
| `documentation_basics` | Met | README (install, configuration, operations), docs/, the site https://guardspec.io/docs/ |
| `documentation_interface` | Met | README "APIs" (gateway and control-plane endpoints) and "Configuration" (every variable) |
| `sites_https` | Met | https://github.com/guard-spec/guard-spec, https://guardspec.io (HTTPS), releases and ghcr.io over HTTPS |
| `discussion` | Met | GitHub issues (searchable, linkable, open to newcomers): https://github.com/guard-spec/guard-spec/issues |
| `english` | Met | Documentation and issues in English; README.vi.md is a Vietnamese translation |
| `maintained` | Met | Active: releases v0.1.0 to v0.3.0 in November 2026, weekly Dependabot |

## Change control

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `repo_public` | Met | https://github.com/guard-spec/guard-spec |
| `repo_track` | Met | git: who changed what and when |
| `repo_interim` | Met | Every change lands through a pull request on `main`, between releases |
| `repo_distributed` | Met | git |
| `version_unique` | Met | Each release has a unique version (`v0.3.0`) |
| `version_semver` | Met | Semantic Versioning, stated in https://github.com/guard-spec/guard-spec/blob/main/CHANGELOG.md |
| `version_tags` | Met | git tags `v*`, release workflow runs on them |
| `release_notes` | Met | https://github.com/guard-spec/guard-spec/blob/main/CHANGELOG.md (Keep a Changelog) and the GitHub release notes |
| `release_notes_vulns` | N/A | No release has fixed a publicly known vulnerability with a CVE yet. **owner**: switch to Met with the first advisory |

## Reporting

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `report_process` | Met | Issue forms (bug, bypass, false positive, feature): https://github.com/guard-spec/guard-spec/issues/new/choose |
| `report_tracker` | Met | GitHub issues |
| `report_responses` | Met | **owner**: confirm a majority of bug reports in the last 2 to 12 months were acknowledged |
| `enhancement_responses` | Met | **owner**: confirm a majority of enhancement requests were answered |
| `report_archive` | Met | Issues and pull requests are public and searchable |
| `vulnerability_report_process` | Met | https://github.com/guard-spec/guard-spec/blob/main/SECURITY.md "Reporting a vulnerability" |
| `vulnerability_report_private` | Met | GitHub private vulnerability reporting (https://github.com/guard-spec/guard-spec/security/advisories/new) or security@guardspec.io. **owner**: confirm private reporting is enabled in Settings > Code security |
| `vulnerability_report_response` | Met | Target: acknowledgement within 3 business days (https://github.com/guard-spec/guard-spec/blob/main/SECURITY.md "Response targets"). **owner**: if no report came in the last 6 months, say so |

## Quality

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `build` | Met | `go build ./...`; `make`; GoReleaser for releases (https://github.com/guard-spec/guard-spec/blob/main/.goreleaser.yaml) |
| `build_common_tools` | Met | Go toolchain, make, Docker, npm |
| `build_floss_tools` | Met | All build tools are FLOSS |
| `test` | Met | `go test -race ./...`, integration tests with Postgres, admin UI unit and Playwright tests (https://github.com/guard-spec/guard-spec/blob/main/CONTRIBUTING.md "Tests") |
| `test_invocation` | Met | `go test ./...` (standard for Go); `make test` |
| `test_most` | Met | Unit tests across internal/ and cmd/; integration tests for the database paths; detector eval against a baseline |
| `test_continuous_integration` | Met | https://github.com/guard-spec/guard-spec/blob/main/.github/workflows/ci.yml on every pull request and push to `main` |
| `test_policy` | Met | https://github.com/guard-spec/guard-spec/blob/main/CONTRIBUTING.md "Pull requests": new functionality comes with tests, bug fixes with a regression test |
| `tests_are_added` | Met | Recent feature pull requests add tests (for example the v0.3.0 changes in https://github.com/guard-spec/guard-spec/blob/main/CHANGELOG.md). **owner**: confirm |
| `tests_documented_added` | Met | The test policy is in CONTRIBUTING.md and the pull request template asks "How it was tested" (https://github.com/guard-spec/guard-spec/blob/main/.github/PULL_REQUEST_TEMPLATE.md) |
| `warnings` | Met | `go vet` and golangci-lint in CI; `npm run lint` and `typecheck` for the admin UI |
| `warnings_fixed` | Met | CI fails on new vet and lint findings (golangci-lint `only-new-issues`) |
| `warnings_strict` | Met | golangci-lint runs on every pull request; `helm lint --strict` for the chart |

## Security

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `know_secure_design` | Met | **owner** self-assessment. Evidence of practice: https://github.com/guard-spec/guard-spec/blob/main/docs/security/README.md (architecture, threat model), https://github.com/guard-spec/guard-spec/blob/main/docs/security-risks.md |
| `know_common_errors` | Met | **owner** self-assessment. https://github.com/guard-spec/guard-spec/blob/main/docs/security-risks.md lists the risks and mitigations |
| `crypto_published` | Met | Only published algorithms: bcrypt, AES-256-GCM, SHA-256, HMAC, TLS, Sigstore (https://github.com/guard-spec/guard-spec/blob/main/docs/security/README.md "Encryption") |
| `crypto_call` | Met | Go standard library `crypto/*` and `golang.org/x/crypto/bcrypt`; no own implementations |
| `crypto_floss` | Met | All of the above are FLOSS |
| `crypto_keylength` | Met | AES-256; `JWT_SECRET` at least 32 bytes and `MFA_ENC_KEY` 32 bytes, enforced at start outside dev mode |
| `crypto_working` | Met | No MD4, MD5, single DES, RC4 or Dual_EC_DRBG |
| `crypto_weakened` | Met | SHA-1 appears only where an external standard fixes it: HMAC-SHA1 for TOTP (RFC 6238, what authenticator apps use) and git blob ids returned by the Hugging Face API, after which the SHA-256 is pinned |
| `crypto_pfs` | Met | TLS is terminated in front of the services by the deployment; outgoing TLS uses Go's crypto/tls (TLS 1.2+, ECDHE suites) |
| `crypto_password_storage` | Met | bcrypt for passwords and recovery codes; API keys and one-time tokens stored as SHA-256 |
| `crypto_random` | Met | `crypto/rand` for keys, tokens and codes |
| `delivery_mitm` | Met | Releases over HTTPS; images and checksum files signed with cosign keyless; SLSA provenance (https://github.com/guard-spec/guard-spec/blob/main/docs/security/verifying-releases.md) |
| `delivery_unsigned` | Met | No hash is fetched over HTTP; checksums are signed |
| `vulnerabilities_fixed_60_days` | Met | No known unpatched vulnerability of medium or higher severity older than 60 days: OSV (Scorecard's Vulnerabilities check) finds none once the LlamaIndex example locks Pillow 13; Dependabot and govulncheck run continuously |
| `vulnerabilities_critical_fixed` | Met | Same, plus the targets in https://github.com/guard-spec/guard-spec/blob/main/SECURITY.md "Response targets" |
| `no_leaked_credentials` | Met | No credentials in the repository; dev-only defaults are refused outside `GUARD_ENV=dev`; GitHub secret scanning. **owner**: confirm secret scanning is on |

## Analysis

| Criterion | Answer | Justification / evidence |
|---|---|---|
| `static_analysis` | Met | CodeQL (Go, Python) on every push and pull request (https://github.com/guard-spec/guard-spec/blob/main/.github/workflows/codeql.yml), golangci-lint, govulncheck |
| `static_analysis_common_vulnerabilities` | Met | CodeQL security queries; govulncheck |
| `static_analysis_fixed` | Met | Findings are triaged in the Security tab; none of medium or higher severity is open. **owner**: confirm in Security > Code scanning |
| `static_analysis_often` | Met | On every commit |
| `dynamic_analysis` | Met | Go native fuzzing (`make fuzz`: sanitizer, policy, request fuzzers, cmd/gateway/fuzz_test.go), `go test -race`, Playwright end-to-end tests |
| `dynamic_analysis_unsafe` | N/A | Go is memory-safe. The onnx build calls ONNX Runtime through cgo; its tests run with `-race` in the onnx CI job |
| `dynamic_analysis_enable_assertions` | Met | The race detector and fuzzers run with the test assertions enabled |
| `dynamic_analysis_fixed` | Met | No open finding of medium or higher severity |

## Not met, or only the owner can answer

- Nothing at the passing level is known to be unmet. The **owner** items
  above are statements a maintainer must make (response history, private
  reporting and secret scanning switched on, self-assessment of secure design
  knowledge).
- Silver and gold are out of reach for now, mostly because of the single
  maintainer: they need at least two unassociated significant contributors
  (`contributors_unassociated`), a bus factor of two or more (`bus_factor`),
  and two-person review of changes (`two_person_review`, gold). The same is
  why Scorecard's Code-Review and Contributors checks stay low.

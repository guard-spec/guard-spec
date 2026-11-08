# Security Policy

Guard Spec is a security component: it sits in front of LLMs and decides what
reaches them. We treat bypasses of its guardrails as vulnerabilities, not only
classic memory-safety or authentication bugs.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report it privately through GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**
   (direct link: `https://github.com/guard-spec/guard-spec/security/advisories/new`).
3. Describe the issue, the affected version or commit, and how to reproduce it.
   A minimal request body or proof of concept helps most.

If you cannot use GitHub, email **security@guardspec.io** with the same
details. Please do not put details in a public issue.

### What we consider in scope

- Bypassing the sanitizer, classifier thresholds or policy engine so that text
  the gateway should block or clean reaches the upstream model.
- Cross-tenant access: reading or changing another organization's data,
  including through row-level security gaps.
- Authentication or authorization flaws in the control plane or gateway
  (API keys, JWTs, roles).
- Leaks of prompts, responses, API keys or other secrets, including through
  logs or audit rows.
- Insecure defaults that survive outside development mode (`GUARD_ENV=dev`).
- Vulnerabilities in our container images or release artifacts.

Out of scope: findings that require `GUARD_ENV=dev` or the development compose
override, model accuracy without a concrete bypass, denial of service by
volume alone, and issues in upstream LLMs.

### Guardrail bypasses: public issue or private report

No classifier catches every attack, so a single text that gets past the
detector is usually not a vulnerability: report it with the public "Bypass"
issue form, and it becomes training or hold-out data
([docs/red-team.md](docs/red-team.md)). Report a bypass **privately**, as
above, when it is severe: it would let an attacker exfiltrate data, call
tools or reach another tenant in a real deployment, or it is a general
technique (an encoding, a sanitizer gap, a policy-engine flaw) that defeats
every layer for a whole class of texts. When in doubt, report privately.

## Hardening

For the risks that remain when you run Guard Spec and how to reduce them, see
[docs/security-risks.md](docs/security-risks.md).

For a security review of a deployment (architecture, data flow, what is
stored where and for how long, secrets and encryption), see
[docs/security/](docs/security/README.md).

## Supported versions

The project is pre-1.0. Security fixes land on `main` and in the next release.

| Version          | Supported          |
| ---------------- | ------------------ |
| `main`           | Yes                |
| latest `0.x`     | Yes                |
| older `0.x`      | No, please upgrade |

After 1.0 the latest minor release and the one before it will receive fixes.

## Response targets

These are targets, not guarantees, for a small volunteer team:

| Step                                   | Target                      |
| -------------------------------------- | --------------------------- |
| Acknowledge the report                 | 3 business days             |
| Initial assessment and severity        | 7 days                      |
| Fix for critical or high severity      | 30 days                     |
| Fix for medium or low severity         | 90 days                     |
| Public advisory                        | when the fix is released    |

We will keep you informed while we work on it, credit you in the advisory
unless you prefer otherwise, and request a CVE where it applies. Please give us
the time above before disclosing publicly; we will agree a date with you if a
fix needs longer.

## Known vulnerabilities in dependencies and images

No release ships with a known vulnerability that has a fix. Every pull
request, every push to `main` and a daily scheduled run scan the Go, npm and
Python lockfiles and the gateway and control-plane images with Trivy, and
govulncheck checks the Go code; a finding with a fixed version fails CI. The
daily run also scans the images of the latest release and opens an issue
labelled `security` for what it finds. Details:
[docs/security/vulnerabilities.md](docs/security/vulnerabilities.md).

When a vulnerability is published in something a release contains:

| Severity (CVSS)  | Patch release with the fix |
| ---------------- | -------------------------- |
| Critical         | within 48 hours            |
| High             | within 7 days              |
| Medium or low    | in the next release, at most 30 days |

The clock starts when a fixed version of the dependency or base image is
available. A vulnerability that does not affect Guard Spec (the code is not
reachable, or the component is not used) is recorded with the reason in
[`.vex/guard-spec.openvex.json`](.vex/guard-spec.openvex.json) instead, and
the advisory lists it. `doctor` reports a published Guard Spec advisory that
affects the running version.

## Verifying releases

[docs/security/verifying-releases.md](docs/security/verifying-releases.md)
has the full procedure (signatures pinned to the release tag, SBOMs, SLSA
provenance) with its output for v0.2.0. In short:

Release container images are signed with cosign (keyless, through GitHub
Actions OIDC) and come with an SPDX SBOM and SLSA provenance (BuildKit
attestations; `docker buildx imagetools inspect <image> --format '{{json .SBOM}}'`).
The gateway and gateway-full images are built by `.github/workflows/release.yml`,
the control-plane image by GoReleaser; all are verified the same way (replace
`guard-spec-gateway` with `guard-spec-gateway-full` or `guard-spec-control-plane`):

```bash
cosign verify ghcr.io/guard-spec/guard-spec-gateway:<version> \
  --certificate-identity-regexp '^https://github.com/guard-spec/guard-spec/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Archives are covered by `checksums.txt` (GoReleaser, L1-only binaries) and
`checksums-onnx.txt` (the linux `_onnx` tarballs), each signed with a cosign
bundle next to it:

```bash
cosign verify-blob checksums-onnx.txt --bundle checksums-onnx.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/guard-spec/guard-spec/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums-onnx.txt
```

From the release after v0.3.0, every file those checksums list also has SLSA
build provenance (a GitHub artifact attestation), attached to the release as
`guard-spec_<version>.intoto.jsonl`:

```bash
gh attestation verify guard-spec_<version>_linux_amd64.tar.gz -R guard-spec/guard-spec \
  --bundle guard-spec_<version>.intoto.jsonl \
  --signer-workflow guard-spec/guard-spec/.github/workflows/release.yml
```

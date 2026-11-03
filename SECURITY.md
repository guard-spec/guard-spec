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
   (direct link: `https://github.com/giaplee/guard-spec/security/advisories/new`).
3. Describe the issue, the affected version or commit, and how to reproduce it.
   A minimal request body or proof of concept helps most.

If you cannot use GitHub, say so in a public issue *without any details* and a
maintainer will arrange another private channel.

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

## Verifying releases

Release container images are signed with cosign (keyless, through GitHub
Actions OIDC) and come with an SPDX SBOM. To verify an image:

```bash
cosign verify ghcr.io/giaplee/promptshield-gateway:<version> \
  --certificate-identity-regexp '^https://github.com/giaplee/guard-spec/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

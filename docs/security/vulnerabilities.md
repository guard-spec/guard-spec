<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Vulnerability management

> Tiếng Việt: [vulnerabilities.vi.md](vulnerabilities.vi.md).

The rule: **no release ships with a known vulnerability that has a fix, and a
vulnerability published after a release is fixed by a patch release within
the times in [SECURITY.md](../../SECURITY.md#known-vulnerabilities-in-dependencies-and-images).**
This page says how that is checked and what to do with a finding.

## What is scanned, and when

| What | Tool | Pull request and `main` | Every day (02:41 UTC) |
|---|---|---|---|
| Go code (reachable vulnerable functions) | govulncheck, pinned in `tools/go.mod` | yes (`ci.yml`, required check) | - |
| Lockfiles: `go.mod`, `tools/go.mod`, `web/` and example `package-lock.json`, `train/`, `bench/` and example `uv.lock` | Trivy | yes | yes, on `main` |
| Gateway and control-plane images built from the checkout | Trivy | yes | yes, on `main` |
| Images of the latest release (gateway, gateway-full, control-plane) | Trivy | - | yes |

[`.github/workflows/vuln-scan.yml`](../../.github/workflows/vuln-scan.yml)
runs the Trivy scans; Trivy is installed by
[`scripts/install-trivy.sh`](../../scripts/install-trivy.sh) at a pinned
version whose archive SHA-256 was checked against Trivy's cosign-signed
checksums.

- **Gate.** A finding with a fixed version fails the job, whatever its
  severity. Findings without a fix do not fail it, but every finding goes to
  the repository's Code scanning (Security tab, categories
  `trivy-dependencies` and `trivy-image-*`).
- **Released images.** The daily run scans the images of the latest
  release. Any finding opens, or updates, one issue titled "Known
  vulnerabilities in the v&lt;version&gt; images" with the label `security`,
  and the run fails, so it shows in the Actions tab. The issue is closed by
  the first clean run. A finding there is fixed with a patch release.
- **Dependabot** opens pull requests for Go modules (`/` and `/tools`), npm,
  uv, GitHub Actions and the base image digests (daily for the images).

## Base images

Chainguard's Wolfi images are rebuilt with fixes every day and carry only
what the binaries need. They replaced Debian `bookworm-slim` (gateway,
hundreds of OS-package CVEs without a fix, among them a critical one in
zlib) and distroless static (control plane).

| Image | Base | Contents |
|---|---|---|
| gateway, gateway-full | `cgr.dev/chainguard/glibc-dynamic` | glibc, libgcc, libstdc++, CA certificates; ONNX Runtime is added from its release |
| control-plane | `cgr.dev/chainguard/static` | CA certificates, tzdata, passwd |

Both are pinned by digest. Neither has a shell, a package manager or curl,
so the deployment files call the binaries' own subcommands:

| Was | Now |
|---|---|
| `curl -fsS http://localhost:8080/readyz` (HEALTHCHECK, compose, ECS) | `/app/gateway health` (`/app/gateway health /health` for liveness only) |
| the `models-init` shell script (compose, Helm `models-pull`) | `./models init`: pulls what `DETECTOR_LAYERS` needs; a failed pull warns, or exits 1 with `DETECTOR_REQUIRE_ML=true` / `MODELS_REQUIRED=true` |
| `cp /app/migrations/*.sql /migrations/` (Helm migrations job) | `/app/doctor copy-migrations /migrations /app/migrations` |

Since 0.4.0 the compose files, the Helm chart and the Terraform ECS module
use these forms; the 0.3.x images were the last with a shell (an older
chart's `gateway.image.shell` setting is gone). `internal/version` has a
test that fails if a deployment file goes back to a shell form.

## When a scan finds something

1. **A fixed version exists.** Update the dependency or let the Dependabot
   pull request through (for a base image, the digest bump). If it is in a
   released image, cut a patch release within the time in SECURITY.md.
2. **No fix yet.** It stays visible in Code scanning (and in the issue, for
   a released image). Check whether it affects Guard Spec. Remove the
   component if it is not needed.
3. **It does not affect Guard Spec.** Add an OpenVEX statement with the
   reason to [`.vex/guard-spec.openvex.json`](../../.vex/guard-spec.openvex.json);
   every scan reads that file. Example:

   ```json
   {
     "vulnerability": {"name": "CVE-2026-00000"},
     "products": [{"@id": "pkg:oci/guard-spec-gateway"}],
     "status": "not_affected",
     "justification": "vulnerable_code_not_in_execute_path",
     "impact_statement": "The gateway never calls the affected function; govulncheck reports it unreachable."
   }
   ```

   Statements are reviewed at each release and removed once the dependency
   is updated.

## Checking a running installation

`doctor` (in the gateway and control-plane images) has an `advisories`
check: it reads the project's published GitHub security advisories and
fails when one affects the running version, with the version to upgrade to.
The request carries no identifier of the installation. Without internet
access run `doctor -skip advisories`, or point `DOCTOR_ADVISORIES_URL` at a
mirror of `https://api.github.com/repos/guard-spec/guard-spec/security-advisories?state=published`.

To scan a running image yourself:

```bash
trivy image ghcr.io/guard-spec/guard-spec-gateway:<version>
```

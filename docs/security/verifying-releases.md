<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Verifying a release

Every release is built by `.github/workflows/release.yml` on a `v*` tag, in
GitHub Actions, and signed there with cosign **keyless**: the signing
certificate is issued by Sigstore's Fulcio to that workflow's GitHub OIDC
identity and logged in the Rekor transparency log. No long-lived signing key
exists. What you can check:

| Artifact | Signed | SBOM | Provenance |
|---|---|---|---|
| `ghcr.io/guard-spec/guard-spec-gateway` | cosign, the index and each platform image | SPDX 2.3 per platform (BuildKit attestation) | SLSA v1 per platform (BuildKit, `mode=max`) |
| `ghcr.io/guard-spec/guard-spec-gateway-full` | cosign, the index and each platform image | SPDX 2.3 per platform | SLSA v1 per platform (`mode=max`) |
| `ghcr.io/guard-spec/guard-spec-control-plane` | cosign (GoReleaser) | SPDX 2.3 per platform | SLSA v1 per platform, minimal (no builder id) |
| Release archives (`guard-spec_<version>_<os>_<arch>.tar.gz`) | `checksums.txt` + `checksums.txt.sigstore.json` | `<archive>.sbom.json` (SPDX, syft) | — |
| Linux `_onnx` archives | `checksums-onnx.txt` + `checksums-onnx.txt.sigstore.json` | `<archive>.sbom.json` | — |
| Models | SHA-256 pinned in `models/manifest.yaml` (and `build/gateway-full.l2.sha256` for the image) | — | — |

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.4 or newer (the outputs below are from cosign v3.1.4), `docker buildx`
for the attestations, `jq`, and `sha256sum` (`shasum -a 256` on macOS).

## 1. Image signatures

Pin the identity to the release workflow **at the tag you deploy**. That
proves the image was signed by this repository's release workflow running
for that tag, not by a branch, a fork or another workflow:

```bash
VERSION=0.1.0
for img in guard-spec-gateway guard-spec-gateway-full guard-spec-control-plane; do
  cosign verify "ghcr.io/guard-spec/$img:$VERSION" \
    --certificate-identity "https://github.com/guard-spec/guard-spec/.github/workflows/release.yml@refs/tags/v$VERSION" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    | jq -r '.[0].critical.image."docker-manifest-digest"'
done
```

Output for v0.1.0 (run on 2026-11-06):

```text
Verification for ghcr.io/guard-spec/guard-spec-gateway:0.1.0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
sha256:e765d231b541c6bcbc7f383611b11b8f741b909eaf3c6acd9537e71421fd0929

Verification for ghcr.io/guard-spec/guard-spec-gateway-full:0.1.0 --
  (same three checks)
sha256:802516f061f9e8a23c3de6ec2613a73fa746b137a3d50fd53429057dd231b41d

Verification for ghcr.io/guard-spec/guard-spec-control-plane:0.1.0 --
  (same three checks)
sha256:bba33e596f32fd7853d2b4f8dbf084b03364f8666d99fc5f8a50cdc160be510c
```

A wrong identity fails, which is what makes the check meaningful:

```text
$ cosign verify ghcr.io/guard-spec/guard-spec-gateway:0.1.0 \
    --certificate-identity https://github.com/guard-spec/guard-spec/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
Error: no matching attestations: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value "https://github.com/guard-spec/guard-spec/.github/workflows/release.yml@refs/heads/main", got "https://github.com/guard-spec/guard-spec/.github/workflows/release.yml@refs/tags/v0.1.0"
```

[SECURITY.md](../../SECURITY.md#verifying-releases) shows a looser form,
`--certificate-identity-regexp '^https://github.com/guard-spec/guard-spec/'`,
which accepts any workflow of the repository. Prefer the exact identity.

**Deploy by digest.** A tag can be moved; a digest cannot. Use the digest
printed above in your manifests
(`image: ghcr.io/guard-spec/guard-spec-gateway-full@sha256:...`). With the
Helm chart, set the tag to `0.1.0@sha256:...` (the chart renders
`<repository>:<tag>`); the [Terraform reference](../../deploy/terraform/aws/README.md)
has `*_image_digest` variables. In Kubernetes, an admission controller such as the Sigstore
policy-controller or Kyverno can enforce the same identity on every pull.

## 2. SBOMs

The image SBOMs are BuildKit attestations inside the image index, one per
platform:

```bash
docker buildx imagetools inspect ghcr.io/guard-spec/guard-spec-gateway:0.1.0 \
  --format '{{json .SBOM}}' > gateway-sbom.json
jq -r 'to_entries[] | "\(.key) \(.value.SPDX.spdxVersion) packages=\(.value.SPDX.packages|length)"' gateway-sbom.json
```

```text
linux/amd64 SPDX-2.3 packages=169
linux/arm64 SPDX-2.3 packages=169
```

The same for v0.1.0's other images: `guard-spec-gateway-full` 169 packages
per platform, `guard-spec-control-plane` 65. Feed `.["linux/amd64"].SPDX`
to your scanner (for example `grype sbom:./sbom.spdx.json`). The archive
SBOMs are files on the release, covered by the signed checksums below.

## 3. SLSA provenance

```bash
docker buildx imagetools inspect ghcr.io/guard-spec/guard-spec-gateway:0.1.0 \
  --format '{{json .Provenance}}' > gateway-provenance.json
jq -r 'to_entries[] | "\(.key) builder=\(.value.SLSA.runDetails.builder.id) revision=\(.value.SLSA.buildDefinition.externalParameters.request.args["label:org.opencontainers.image.revision"])"' gateway-provenance.json
git rev-list -n 1 v0.1.0     # in a clone of guard-spec/guard-spec
```

```text
linux/amd64 builder=https://github.com/guard-spec/guard-spec/actions/runs/42084759045/attempts/1 revision=df7e89ef72ed2478eb7b14be8c159ddb337219d3
linux/arm64 builder=https://github.com/guard-spec/guard-spec/actions/runs/42084759045/attempts/1 revision=df7e89ef72ed2478eb7b14be8c159ddb337219d3
df7e89ef72ed2478eb7b14be8c159ddb337219d3
```

The provenance names the workflow run that built the image and the commit
it built, which must be the commit of the tag. `guard-spec-gateway-full`
gives the same run and revision. With `mode=max` it also lists the
Dockerfile, build arguments and every base image by digest
(`.buildDefinition.resolvedDependencies`).

The control-plane image is built by GoReleaser with a minimal provenance
(no builder id). Its signature (step 1) already binds it to the release
workflow at the tag, and its labels name the commit:

```bash
docker buildx imagetools inspect ghcr.io/guard-spec/guard-spec-control-plane:0.1.0 \
  --format '{{json .Image}}' | jq -r '."linux/amd64".config.Labels."org.opencontainers.image.revision"'
# df7e89ef72ed2478eb7b14be8c159ddb337219d3
```

These attestations are unsigned BuildKit documents stored next to the
image; trust them because the image index that references them is the one
whose signature you verified in step 1.

## 4. Release archives

```bash
VERSION=0.1.0
gh release download "v$VERSION" -R guard-spec/guard-spec \
  -p 'checksums*' -p "guard-spec_${VERSION}_linux_amd64*"
for f in checksums.txt checksums-onnx.txt; do
  cosign verify-blob "$f" --bundle "$f.sigstore.json" \
    --certificate-identity "https://github.com/guard-spec/guard-spec/.github/workflows/release.yml@refs/tags/v$VERSION" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done
sha256sum --ignore-missing -c checksums.txt checksums-onnx.txt
```

```text
Verified OK
Verified OK
guard-spec_0.1.0_linux_amd64.tar.gz: OK
guard-spec_0.1.0_linux_amd64.tar.gz.sbom.json: OK
guard-spec_0.1.0_linux_amd64_onnx.tar.gz: OK
guard-spec_0.1.0_linux_amd64_onnx.tar.gz.sbom.json: OK
```

`checksums.txt` covers the GoReleaser archives, their SBOMs and the source
archive; `checksums-onnx.txt` covers the linux `_onnx` archives and their
SBOMs.

## 5. Models

`models pull` checks every file against the SHA-256 in
`models/manifest.yaml` of the release you run and refuses a mismatch; see
[docs/models.md](../models.md). The `gateway-full` image checks the L2 files
against `build/gateway-full.l2.sha256` while it is built, and its signature
covers the result.

## What this does not prove

- That the source is free of vulnerabilities. Scan the SBOMs; CI runs
  `govulncheck`, CodeQL and OpenSSF Scorecard on the repository.
- That a build is reproducible bit for bit. Binaries are built with
  `-trimpath` and the commit timestamp, but nobody has published an
  independent rebuild yet.
- Anything about images you rebuilt or mirrored: verify before mirroring, and
  deploy the digest you verified.

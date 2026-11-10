<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Air-gapped and mirrored installs (Kubernetes)

> Tiếng Việt: [airgapped.vi.md](airgapped.vi.md).

How to run the Helm chart (`deploy/helm/guard-spec`) on a cluster that cannot
reach ghcr.io, Docker Hub or Hugging Face: mirror the images with their
signatures and attestations, mirror the models, verify everything offline,
and point the chart at the mirrors. The same steps work for a cluster that
may only pull from an internal registry.

> **Status: reference, not yet verified by the maintainers on a disconnected
> cluster.** The cosign commands below were run against the 0.1.0 images;
> the chart values are checked by CI (`helm lint`, `kubeconform`) and the
> kind e2e. Reports are welcome, see [docs/deploy/README.md](deploy/README.md).

[docs/models.md](models.md#air-gapped-installs) covers the models alone, and
[docs/deploy/on-premise.md](deploy/on-premise.md) the compose path.

## 1. What to move

| What | Source | Used by |
|---|---|---|
| Gateway image | `ghcr.io/guard-spec/guard-spec-gateway:<version>` | gateway pods; also the `migrations` hook (it copies `/app/migrations`) and the `models.pull` init container |
| or gateway-full | `ghcr.io/guard-spec/guard-spec-gateway-full:<version>` | gateway with the L2/L3 models inside: no model mirror needed |
| Control plane image | `ghcr.io/guard-spec/guard-spec-control-plane:<version>` | control plane pods |
| golang-migrate | `migrate/migrate:v4.20.1@sha256:76cc2074cb6642631f34a898ced71e6aeaa6b1a4d78c4daa743275a22e0c5be7` | `migrations.enabled` |
| Postgres client | `postgres:17.11-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b` | `dbRoles.enabled` |
| Models | the files of `models/manifest.yaml` (about 250 MB for the recommended L2 + L3) | `models.pull` |
| Chart | `deploy/helm/guard-spec` of the release tag (also inside every release archive) | `helm install` |
| Sigstore trusted root | `trusted_root.json` | offline signature checks |

The Guard Spec images are signed with cosign (keyless, GitHub Actions OIDC)
and carry an SPDX SBOM and SLSA provenance as BuildKit attestations inside
the image index ([SECURITY.md](../SECURITY.md)). The two third-party images
are not ours: pin them by digest, as above.

## 2. On the connected side

```bash
V=0.5.0
ID='^https://github.com/guard-spec/guard-spec/'
ISSUER=https://token.actions.githubusercontent.com

# The trusted root (Fulcio CA, Rekor and CT log keys) for offline checks.
# cosign keeps the copy it fetched over TUF here after any online verify:
cosign verify ghcr.io/guard-spec/guard-spec-gateway:$V \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" >/dev/null
cp ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json .

# Each image with its signature and attestations, as an OCI layout on disk.
for img in guard-spec-gateway guard-spec-control-plane; do   # + guard-spec-gateway-full
  cosign save --dir "out/$img" "ghcr.io/guard-spec/$img:$V"
done
# Third-party images: every platform, digest unchanged.
skopeo copy --all docker://migrate/migrate:v4.20.1@sha256:76cc2074cb6642631f34a898ced71e6aeaa6b1a4d78c4daa743275a22e0c5be7 oci:out/migrate:v4.20.1
skopeo copy --all docker://postgres:17.11-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b oci:out/postgres:17.11-alpine

# Models: the recommended versions, every file checked against the manifest
# (the release archive's models tool has the release's manifest built in;
# it also holds the chart, under deploy/).
./models pull -dir out/models
./models verify -dir out/models
```

`cosign save` writes the image index as it is, with its per-platform
manifests, the BuildKit SBOM and provenance attestation manifests, and the
cosign signature. `skopeo copy --all` (or `oras cp -r`, `crane copy`) keeps
digests; `docker pull` + `docker push` keeps only one platform and changes
the index digest.

Carry `out/`, `trusted_root.json` and the release archive (or `helm package
deploy/helm/guard-spec`) across.

## 3. Verify offline, then load into the registry

No network is needed: the signature bundles carry the Rekor inclusion proof,
and `trusted_root.json` replaces the TUF lookup.

```bash
for img in guard-spec-gateway guard-spec-control-plane; do
  cosign verify --local-image "out/$img" --trusted-root trusted_root.json \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"
done

REG=registry.internal/guard-spec
for img in guard-spec-gateway guard-spec-control-plane; do
  cosign load --dir "out/$img" "$REG/$img:$V"
  # Again from the registry: the signature travelled with the image.
  cosign verify "$REG/$img:$V" --trusted-root trusted_root.json \
    --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"
done
skopeo copy --all oci:out/migrate:v4.20.1 docker://$REG/migrate:v4.20.1
skopeo copy --all oci:out/postgres:17.11-alpine docker://$REG/postgres:17.11-alpine

# The SBOM and provenance stay readable from the mirror:
docker buildx imagetools inspect "$REG/guard-spec-gateway:$V" --format '{{json .Provenance}}' | head
```

The release archives are checked the same way:
`cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json --trusted-root trusted_root.json --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"`,
then `sha256sum --ignore-missing -c checksums.txt`.

To enforce signatures at admission, give the cluster's policy engine
(Sigstore policy-controller, Kyverno `verifyImages`) the same identity, issuer
and trusted root.

## 4. Mirror the models

`models pull` reads `<mirror>/<name>/<version>/<file>`, which is the layout
of `out/models` (`models/cache`). Serve that directory from any static HTTP
server inside the network (nginx, an S3, GCS or Azure Blob bucket, Artifactory
generic repository). The mirror does not need to be trusted: every file is
checked against the SHA-256 in the image's own `manifest.yaml`, and a mismatch
is refused.

```bash
aws s3 sync out/models s3://models-internal/guard-spec/   # for example
```

Alternatively use `guard-spec-gateway-full` and skip the model mirror.

## 5. Point the chart at the mirrors

```yaml
# values-airgapped.yaml
imagePullSecrets:
  - name: registry-internal
gateway:
  image:
    repository: registry.internal/guard-spec/guard-spec-gateway
    tag: "0.5.0"          # or "0.5.0@sha256:<index digest>" to pin the digest
controlPlane:
  image:
    repository: registry.internal/guard-spec/guard-spec-control-plane
    tag: "0.5.0"
migrations:
  enabled: true
  image:
    repository: registry.internal/guard-spec/migrate
    tag: v4.20.1
    # Same digest as Docker Hub when copied with skopeo --all; else empty it.
    digest: sha256:76cc2074cb6642631f34a898ced71e6aeaa6b1a4d78c4daa743275a22e0c5be7
dbRoles:
  enabled: true
  image:
    repository: registry.internal/guard-spec/postgres
    tag: 17.11-alpine
models:
  persistence:
    enabled: false       # each pod pulls into its own emptyDir; or keep a claim
  pull:
    enabled: true
    required: true       # a model that cannot be pulled stops the pod
    mirror: https://models.internal/guard-spec
networkPolicy:
  enabled: true
  egress:
    restrict: true
    gateway:
      - to: [{ipBlock: {cidr: 10.20.0.0/16}}]   # the models mirror and the LLM endpoint
        ports: [{port: 443, protocol: TCP}]
```

With gateway-full instead: `gateway.image.repository=.../guard-spec-gateway-full`,
`models.persistence.enabled=false` and no `models.pull`.

Then, as in the README ("Kubernetes"):

```bash
helm install gs ./guard-spec-0.5.0.tgz -n guard-spec -f values-airgapped.yaml
kubectl -n guard-spec exec deploy/gs-guard-spec-gateway -c gateway -- ./doctor
```

`doctor` (in the images from 0.2.0) checks the database and migration version, the model files against
the manifest's SHA-256, which detection layers will load, the upstream and the
security settings; exit code 1 means a check failed.

## 6. Secrets from an external store (External Secrets Operator)

The chart reads every secret from `existingSecret` (default
`guard-spec-secrets`) and never stores one in values. With the
[External Secrets Operator](https://external-secrets.io) that Secret is
created and refreshed from a store such as HashiCorp Vault, which usually
runs inside the disconnected network. The keys are those of `values.yaml`:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: vault
  namespace: guard-spec
spec:
  provider:
    vault:
      server: https://vault.internal:8200
      path: secret
      version: v2
      caProvider: {type: ConfigMap, name: internal-ca, key: ca.crt}
      auth:
        kubernetes:
          mountPath: kubernetes
          role: guard-spec
          serviceAccountRef: {name: guard-spec-eso}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: guard-spec-secrets
  namespace: guard-spec
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: vault}
  target:
    name: guard-spec-secrets        # = existingSecret
    creationPolicy: Owner
  data:
    - {secretKey: POSTGRES_PASSWORD,      remoteRef: {key: guard-spec/db, property: owner_password}}
    - {secretKey: GUARDSPEC_APP_PASSWORD, remoteRef: {key: guard-spec/db, property: app_password}}
    - {secretKey: JWT_SECRET,             remoteRef: {key: guard-spec/control-plane, property: jwt_secret}}
    - {secretKey: MFA_ENC_KEY,            remoteRef: {key: guard-spec/control-plane, property: mfa_enc_key}}
    - {secretKey: ADMIN_PASSWORD,         remoteRef: {key: guard-spec/control-plane, property: admin_password}}
---
# Upstream keys for the gateway: gateway.extraEnvFrom: [{secretRef: {name: guard-spec-upstream}}]
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: guard-spec-upstream
  namespace: guard-spec
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: vault}
  target: {name: guard-spec-upstream}
  data:
    - {secretKey: UPSTREAM_LLM_KEY, remoteRef: {key: guard-spec/upstream, property: api_key}}
```

Notes:

- The services read secrets at start. After a rotation, restart them
  (`kubectl rollout restart deployment -l app.kubernetes.io/instance=gs`), and
  run `helm upgrade` (or the `dbRoles` job) after rotating
  `GUARDSPEC_APP_PASSWORD` so that the database role gets the new password.
- `MFA_ENC_KEY` must stay the one that encrypted the users' TOTP secrets: back
  it up with the database and never let the store generate a new one.
- The chart's own service account (`serviceAccount.create`) is for the
  services, which never call the Kubernetes API; give the operator its own
  account (`guard-spec-eso` above) for the Vault Kubernetes login. With a
  cloud store, swap the provider (AWS Secrets Manager with IRSA, GCP Secret
  Manager or Azure Key Vault with Workload Identity); the `ExternalSecret`
  stays the same.

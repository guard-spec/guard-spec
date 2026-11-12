<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cài đặt air-gapped và qua mirror (Kubernetes)

> English: [airgapped.md](airgapped.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Trang này hướng dẫn chạy Helm chart (`deploy/helm/guard-spec`) trên một
cluster không truy cập được ghcr.io, Docker Hub hay Hugging Face: mirror các
image cùng chữ ký và attestation của chúng, mirror các model, kiểm tra mọi thứ
khi không có mạng, rồi trỏ chart tới các mirror. Các bước này cũng dùng được
cho cluster chỉ được phép pull từ một registry nội bộ.

> **Trạng thái: tài liệu tham khảo, các maintainer chưa kiểm chứng trên một
> cluster bị ngắt mạng.** Các lệnh cosign bên dưới đã được chạy với image
> 0.1.0; values của chart được CI kiểm tra (`helm lint`, `kubeconform`) và
> bài e2e trên kind. Rất hoan nghênh báo cáo của bạn, xem
> [docs/deploy/README.vi.md](deploy/README.vi.md).

[docs/models.md](models.md#air-gapped-installs) chỉ nói riêng về model, còn
[docs/deploy/on-premise.md](deploy/on-premise.md) nói về cách chạy bằng
compose.

## 1. Cần chuyển những gì

| Thứ cần chuyển | Nguồn | Dùng bởi |
|---|---|---|
| Image gateway | `ghcr.io/guard-spec/guard-spec-gateway:<version>` | các pod gateway; cả hook `migrations` (nó copy `/app/migrations`) và init container `models.pull` |
| hoặc gateway-full | `ghcr.io/guard-spec/guard-spec-gateway-full:<version>` | gateway có sẵn model L2/L3 bên trong: không cần mirror model |
| Image control plane | `ghcr.io/guard-spec/guard-spec-control-plane:<version>` | các pod control plane |
| golang-migrate | `migrate/migrate:v4.20.1@sha256:76cc2074cb6642631f34a898ced71e6aeaa6b1a4d78c4daa743275a22e0c5be7` | `migrations.enabled` |
| Postgres client | `postgres:17.11-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b` | `dbRoles.enabled` |
| Model | các file trong `models/manifest.yaml` (khoảng 250 MB cho bộ L2 + L3 khuyến nghị) | `models.pull` |
| Chart | `deploy/helm/guard-spec` của tag release (cũng có trong mọi archive release) | `helm install` |
| Sigstore trusted root | `trusted_root.json` | kiểm tra chữ ký khi không có mạng |

Các image Guard Spec được ký bằng cosign (keyless, GitHub Actions OIDC) và
mang theo SBOM dạng SPDX cùng SLSA provenance dưới dạng attestation của
BuildKit bên trong image index ([SECURITY.md](../SECURITY.md)). Hai image bên
thứ ba không phải của chúng tôi: hãy ghim chúng theo digest như ở trên.

## 2. Ở phía có mạng

```bash
V=0.7.0
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

`cosign save` ghi nguyên image index, gồm các manifest cho từng platform, các
manifest attestation SBOM và provenance của BuildKit, và chữ ký cosign.
`skopeo copy --all` (hoặc `oras cp -r`, `crane copy`) giữ nguyên digest; còn
`docker pull` + `docker push` chỉ giữ một platform và làm đổi digest của
index.

Mang `out/`, `trusted_root.json` và archive release (hoặc `helm package
deploy/helm/guard-spec`) sang phía bên kia.

## 3. Kiểm tra khi không có mạng, rồi nạp vào registry

Không cần mạng: các bundle chữ ký đã chứa bằng chứng inclusion của Rekor, và
`trusted_root.json` thay cho việc tra cứu qua TUF.

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

Các archive release được kiểm tra theo cùng cách:
`cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json --trusted-root trusted_root.json --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER"`,
sau đó `sha256sum --ignore-missing -c checksums.txt`.

Để bắt buộc kiểm tra chữ ký ở bước admission, hãy cấu hình cho policy engine
của cluster (Sigstore policy-controller, Kyverno `verifyImages`) cùng
identity, issuer và trusted root đó.

## 4. Mirror các model

`models pull` đọc theo đường dẫn `<mirror>/<name>/<version>/<file>`, chính là
cấu trúc của `out/models` (`models/cache`). Phục vụ thư mục đó từ bất kỳ HTTP
server tĩnh nào bên trong mạng (nginx, một bucket S3, GCS hoặc Azure Blob,
một generic repository của Artifactory). Mirror không cần được tin cậy: mọi
file đều được đối chiếu với SHA-256 trong chính `manifest.yaml` của image, và
file nào không khớp sẽ bị từ chối.

```bash
aws s3 sync out/models s3://models-internal/guard-spec/   # for example
```

Hoặc dùng `guard-spec-gateway-full` và bỏ qua bước mirror model.

## 5. Trỏ chart tới các mirror

```yaml
# values-airgapped.yaml
imagePullSecrets:
  - name: registry-internal
gateway:
  image:
    repository: registry.internal/guard-spec/guard-spec-gateway
    tag: "0.7.0"          # or "0.7.0@sha256:<index digest>" to pin the digest
controlPlane:
  image:
    repository: registry.internal/guard-spec/guard-spec-control-plane
    tag: "0.7.0"
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

Nếu dùng gateway-full: `gateway.image.repository=.../guard-spec-gateway-full`,
`models.persistence.enabled=false` và không có `models.pull`.

Sau đó, như trong README (phần "Kubernetes"):

```bash
helm install gs ./guard-spec-0.7.0.tgz -n guard-spec -f values-airgapped.yaml
kubectl -n guard-spec exec deploy/gs-guard-spec-gateway -c gateway -- ./doctor
```

`doctor` (có trong image từ 0.2.0) kiểm tra database và phiên bản migration,
đối chiếu các file model với SHA-256 trong manifest, các lớp phát hiện sẽ
được nạp, upstream và các thiết lập bảo mật; exit code 1 nghĩa là có một bước
kiểm tra thất bại.

## 6. Secret từ kho bên ngoài (External Secrets Operator)

Chart đọc mọi secret từ `existingSecret` (mặc định `guard-spec-secrets`) và
không bao giờ lưu secret trong values. Với
[External Secrets Operator](https://external-secrets.io), Secret đó được tạo
và làm mới từ một kho như HashiCorp Vault, thường chạy ngay bên trong mạng bị
ngắt. Các key giống như trong `values.yaml`:

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

Lưu ý:

- Các dịch vụ đọc secret khi khởi động. Sau khi xoay vòng secret, hãy khởi
  động lại chúng
  (`kubectl rollout restart deployment -l app.kubernetes.io/instance=gs`), và
  chạy `helm upgrade` (hoặc job `dbRoles`) sau khi xoay vòng
  `GUARDSPEC_APP_PASSWORD` để role trong database nhận mật khẩu mới.
- `MFA_ENC_KEY` phải giữ nguyên là key đã mã hoá các TOTP secret của người
  dùng: sao lưu nó cùng với database và đừng bao giờ để kho tự sinh key mới.
- Service account riêng của chart (`serviceAccount.create`) dành cho các
  dịch vụ, vốn không bao giờ gọi Kubernetes API; hãy cấp cho operator một
  account riêng (`guard-spec-eso` ở trên) để đăng nhập Vault qua Kubernetes.
  Với kho trên cloud, chỉ cần đổi provider (AWS Secrets Manager với IRSA, GCP
  Secret Manager hoặc Azure Key Vault với Workload Identity); `ExternalSecret`
  giữ nguyên.

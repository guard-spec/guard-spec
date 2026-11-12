<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Hướng dẫn triển khai

> English: [README.md](README.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Các hướng dẫn tham khảo để chạy Guard Spec ở nơi khác ngoài laptop.

> **Trạng thái: template tham khảo, maintainer chưa kiểm chứng.**
> Cộng đồng đã thử: chưa. Nếu bạn triển khai theo các hướng dẫn này, hãy mở
> một [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) hoặc
> một pull request kể lại điều gì chạy được và điều gì không. Xem
> [CONTRIBUTING.md](../../CONTRIBUTING.md).

| Hướng dẫn | Nội dung | Trạng thái |
|---|---|---|
| [aws.md](aws.md) | EKS với Helm chart, hoặc ECS trên Fargate; RDS for PostgreSQL 17, Secrets Manager, ALB + ACM, CloudWatch | Template, chưa thử trên AWS |
| [gcp.md](gcp.md) | GKE Autopilot với Helm chart, hoặc Cloud Run; Cloud SQL for PostgreSQL 17, Secret Manager, HTTPS load balancer, Cloud Logging | Template, chưa thử trên GCP |
| [on-premise.md](on-premise.md) | Một VM với Docker Compose, Kubernetes thuần và OpenShift, cài đặt air-gapped, reverse proxy cho TLS | Template; cách dùng compose là cách README đã mô tả |

Những gì maintainer đã kiểm tra khi viết các hướng dẫn này, trên một host
Docker cục bộ với các image 0.1.0: các migration chạy được trên PostgreSQL 17
bằng `migrate/migrate:v4.20.1`, `deploy/postgres/set-app-password.sh` đặt được
mật khẩu cho role của ứng dụng, và `guard-spec-gateway-full:0.1.0` cùng
`guard-spec-control-plane:0.1.0` khởi động được với một UID không phải root
bất kỳ (group 0) và root filesystem chỉ đọc, `/readyz` báo
`"layers":["l1","l2","l3"]`. Chưa chạy thử gì riêng cho cloud.

## Đọc trước

Các hướng dẫn này không lặp lại README. Chúng giả định bạn đã biết:

- [Bắt đầu nhanh](../../README.vi.md#bắt-đầu-nhanh) và
  [Production](../../README.md#production): các secret và cách các service
  từ chối secret yếu.
- [Cài từ bản phát hành](../../README.vi.md#cài-từ-bản-phát-hành): các image
  và archive.
- [Model](../../README.vi.md#model) và [docs/models.vi.md](../models.vi.md):
  `models pull`, ghim phiên bản, rollback, cài đặt air-gapped.
- [Cấu hình](../../README.vi.md#cấu-hình): mọi biến môi trường.
- [Vận hành](../../README.md#operations), đặc biệt là
  [Kubernetes](../../README.md#kubernetes) và
  [Danh tính, SSO và xác thực hai lớp](../../README.md#identity-sso-and-two-factor-authentication).
- [Mô hình bảo mật và giới hạn](../../README.vi.md#mô-hình-bảo-mật-và-giới-hạn).

## Mọi bản triển khai đều cần

| Thành phần | Ghi chú |
|---|---|
| PostgreSQL | Compose và CI dùng bản 17. Hai role: một role owner chạy migration (`ps` trong compose) và `guardspec_app`, được migration 004 tạo ra không có mật khẩu. Role có phạm vi toàn cluster, nên 004 sẽ lỗi trên server đã có sẵn `guardspec_app` (của một database hoặc một bản cài khác): hãy cho mỗi bản cài một server riêng |
| Migration | `migrations/` của tag bản phát hành, chạy bằng `migrate` dưới role owner, trước khi các service khởi động. Bản thân các service không bao giờ chạy migration; Helm chart chạy khi `migrations.enabled=true` (một hook pre-install / pre-upgrade), nếu không thì bạn tự chạy |
| Mật khẩu ứng dụng | `GUARDSPEC_APP_PASSWORD` được đặt cho `guardspec_app` sau mỗi lần chạy migration: bằng `deploy/postgres/set-app-password.sh` hoặc job `dbRoles` của chart |
| Gateway | `ghcr.io/guard-spec/guard-spec-gateway:0.6.0` (model được mount ở `/models`) hoặc `-gateway-full:0.6.0` (model nằm sẵn trong image). Port 8080 cho client, 9090 cho metrics |
| Control plane | `ghcr.io/guard-spec/guard-spec-control-plane:0.6.0`. Port 8081 cho API và giao diện quản trị ở `/ui/`, 9091 cho metrics |
| Secret | `GUARDSPEC_APP_PASSWORD` (cả hai service, dưới dạng `PGPASSWORD`), `JWT_SECRET`, `MFA_ENC_KEY` và `ADMIN_PASSWORD` (control plane), mật khẩu owner (chỉ dùng cho migration), `UPSTREAM_LLM_KEY` / `UPSTREAM_KEY_*` (gateway) |
| TLS | Các service chỉ nói HTTP thường. Hãy terminate TLS ở load balancer hoặc reverse proxy đứng trước chúng |

## Những điều đúng ở mọi nơi

- **`MFA_ENC_KEY` phải được sao lưu cùng với database.** Key này mã hoá TOTP
  secret của mọi user. Khôi phục một database mà không có đúng key đi kèm sẽ
  khoá tất cả những ai đã bật 2FA, và control plane từ chối khởi động khi
  thiếu key này một khi đã có user bật 2FA.
- **Giữ control plane ở mạng riêng.** Chỉ port 8080 của gateway cần tới được
  các ứng dụng của bạn. Control plane (API và giao diện quản trị) và cả hai
  port metrics nên nằm trong mạng nội bộ, sau VPN hoặc sau một
  identity-aware proxy.
- **`/readyz` chỉ trả 503 khi thiếu một lớp bắt buộc.** Với
  `DETECTOR_REQUIRE_ML=true` (được đặt sẵn trong `gateway-full`), thiếu một
  lớp model sẽ khiến gateway dừng ngay khi khởi động (hoặc, với
  `GUARD_ENV=dev`, khiến `/readyz` trả 503). Không có biến này, một gateway
  thiếu model sẽ chỉ chạy L1 và vẫn báo sẵn sàng kèm `"degraded":true`. Hãy
  kiểm tra `detector.layers` và `detector.degraded` trong smoke test.
- **Rate limit tính theo từng replica gateway** và nằm trong bộ nhớ. Để chống
  lạm dụng, hãy đặt một rate limiter hoặc WAF đứng trước.
- **Streaming.** `UPSTREAM_LLM_TIMEOUT` mặc định là `5m` không có dữ liệu.
  Timeout idle hoặc timeout response của load balancer ngắn hơn câu trả lời
  dài nhất của model sẽ cắt ngang stream; hãy tăng chúng lên.
- **Schema còn thay đổi trước bản 1.0.** Đọc [CHANGELOG](../../CHANGELOG.md)
  và snapshot database trước mỗi lần nâng cấp.

## Helm chart trên `main`

Chart 0.4.0 (xem mục Unreleased trong [CHANGELOG](../../CHANGELOG.md)) bổ
sung các tính năng sau, tất cả đều tắt theo mặc định: một **migration hook**
(`migrations.enabled`), một **init container kéo model** (`models.pull`, kéo
vào claim hoặc vào một `emptyDir` riêng cho từng pod, nên nhiều replica không
còn cần volume ReadWriteMany), **Ingress** và **Routes** của OpenShift,
**HPA**, **PodDisruptionBudget**, **topologySpreadConstraints**,
**NetworkPolicies** và một **ServiceAccount** có annotation cho IRSA và
Workload Identity. Values tham khảo cho từng nền tảng nằm trong
[`deploy/helm/guard-spec/examples/`](../../deploy/helm/guard-spec/examples/)
(EKS, AKS, GKE, OpenShift): được render và kiểm tra schema trong CI, được job
`kind-e2e` cài lên kind với values riêng của job, chưa kiểm chứng trên cloud.
Chỗ nào hướng dẫn bên dưới dùng manifest thuần cho một trong các tính năng
này, thì giờ values của chart đã làm được việc tương tự.

Registry mirror và cluster không kết nối mạng: [../airgapped.vi.md](../airgapped.vi.md)
(image kèm chữ ký và attestation của cosign, model, xác minh offline, values
của chart, External Secrets). Sau khi cài,
`kubectl exec deploy/<release>-guard-spec-gateway -c gateway -- ./doctor`
(image từ 0.2.0) sẽ kiểm tra database, migration, model, các lớp phát hiện,
upstream và các thiết lập bảo mật.

Từ chart 0.1.1 (xem [CHANGELOG](../../CHANGELOG.md)): `/models` chỉ được
mount khi có models claim (hoặc `models.pull`), nên
`guard-spec-gateway-full` chạy được với
`models.persistence.enabled=false`; gateway mặc định giới hạn bộ nhớ 2Gi;
job `dbRoles` lấy securityContext từ values và để OpenShift tự chọn UID; và
`MFA_ENC_KEY` có thể nằm trong `existingSecret`.

**Patch output của chart.** Helm 4 chỉ chấp nhận plugin post-renderer cho
`--post-renderer`; một script thông thường, như Helm 3 từng cho phép, sẽ bị
từ chối (`plugin ... not found`). Để thêm patch kustomize, hãy bọc script
trong một plugin post-renderer, hoặc render rồi apply mà không qua Helm
release: ghi output của `helm template` vào resources của một kustomization,
rồi chạy `kubectl kustomize <dir> | kubectl apply -f -`. Khi đó các hook như
`dbRoles` chạy như Job bình thường, không còn chạy trước các service.

## GPU (tùy chọn)

CPU là mặc định: image gateway chạy bộ phân loại INT8 trên CPU provider của
ONNX Runtime và không cần gì thêm. [Sizing](../sizing.vi.md) có số đo CPU;
với tài liệu dài (từ 100k token) đường CPU cần nhiều core, và GPU là một tùy
chọn.

Tùy chọn GPU là một image riêng, `ghcr.io/guard-spec/guard-spec-gateway:<version>-gpu`
(chỉ linux/amd64, khoảng 5,7 GB khi giải nén, ký bằng cosign như các image khác): cùng
binary gateway, với bản CUDA 12 của ONNX Runtime trên image runtime CUDA 12 +
cuDNN 9 của NVIDIA (`build/gateway-gpu.Dockerfile`). Cần:

- GPU NVIDIA với driver 525 trở lên;
- NVIDIA container runtime (`docker run --gpus all ...`), hoặc trên
  Kubernetes là NVIDIA device plugin hay GPU Operator;
- bộ phân loại FP16, `model_fp16.onnx`, đặt cạnh bản INT8:
  `./models pull -provider cuda` (init container `models.pull` làm việc này
  khi bật `gateway.gpu.enabled`). Nếu thiếu, CUDA chạy model INT8, chậm, và
  `doctor` cảnh báo.

`INFERENCE_PROVIDER` chọn provider (image `-gpu` đặt sẵn `cuda`):

| Giá trị | Hành vi |
|---|---|
| `cpu` | Mặc định. CPU provider, model INT8; không có gì thay đổi. |
| `cuda` | CUDA execution provider trên `INFERENCE_CUDA_DEVICE_ID` (mặc định 0), model FP16. Nếu CUDA không khởi động được (không có GPU, không có driver, dùng nhầm image CPU) thì gateway dừng ngay lúc khởi động với lỗi nói rõ thiếu gì, thay vì âm thầm chạy chậm trên CPU. |
| `auto` | Dùng CUDA nếu khởi động được, nếu không thì chạy CPU kèm cảnh báo (lý do có trong `/readyz`). |

Trên CUDA, `INFERENCE_BATCH_SIZE` mặc định là 64 cửa sổ mỗi lượt chạy (cả
đường ngắn lẫn đường dài) và `INFERENCE_MAX_CONCURRENCY` là 2; chỉnh theo số
đo GPU trong [sizing](../sizing.vi.md). `GET /readyz` báo `detector.inference`
(provider yêu cầu và đang chạy, GPU, driver, phiên bản CUDA và ONNX Runtime,
batch size, `l2_model_file`), và `./doctor` kiểm tra cùng các điều đó trước
khi gateway khởi động (`inference`).

Với Helm chart:

```yaml
gateway:
  gpu:
    enabled: true     # image -gpu, resources.limits["nvidia.com/gpu"]: 1, INFERENCE_PROVIDER=cuda
    # provider: auto  # chạy CPU thay vì từ chối khởi động
  nodeSelector:
    nvidia.com/gpu.present: "true"
  tolerations:
    - {key: nvidia.com/gpu, operator: Exists, effect: NoSchedule}
models:
  pull:
    enabled: true     # tải thêm model_fp16.onnx
```

`ci/gpu-values.yaml` của chart được render và kiểm schema trong CI. Bản thân
image GPU được build trong CI trên máy không có GPU, nơi nó phải từ chối khởi
động với `cuda` và chuyển sang CPU với `auto`; số đo GPU được đo riêng và ghi
rõ trong [sizing](../sizing.vi.md).

## Đóng góp

Nếu bạn chạy Guard Spec trên một trong các nền tảng này, một báo cáo ngắn
hữu ích hơn một hướng dẫn trau chuốt: nền tảng và phiên bản, những gì bạn đã
thay đổi so với hướng dẫn, và những gì bị lỗi. Hãy mở một
[issue](https://github.com/guard-spec/guard-spec/issues/new/choose) hoặc một
pull request vào `docs/deploy/` (xem [CONTRIBUTING.md](../../CONTRIBUTING.md);
commit cần có DCO sign-off). Vấn đề bảo mật phải đi qua
[SECURITY.md](../../SECURITY.md), không bao giờ qua issue công khai.

<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quản lý lỗ hổng

> English: [vulnerabilities.md](vulnerabilities.md).

Quy tắc: **không phát hành bản nào còn lỗ hổng đã biết mà đã có bản vá; lỗ
hổng công bố sau ngày phát hành được vá bằng một bản patch trong thời hạn ở
[SECURITY.md](../../SECURITY.md#known-vulnerabilities-in-dependencies-and-images).**
Trang này nói cách kiểm tra và cách xử lý khi phát hiện.

## Quét gì, khi nào

| Đối tượng | Công cụ | Pull request và `main` | Hằng ngày (02:41 UTC) |
|---|---|---|---|
| Code Go (hàm có lỗ hổng mà code gọi tới) | govulncheck, pin trong `tools/go.mod` | có (`ci.yml`, check bắt buộc) | - |
| Lockfile: `go.mod`, `tools/go.mod`, `package-lock.json` của `web/` và ví dụ, `uv.lock` của `train/`, `bench/` và ví dụ | Trivy | có | có, trên `main` |
| Image gateway và control-plane build từ mã nguồn | Trivy | có | có, trên `main` |
| Image của bản phát hành mới nhất (gateway, gateway-full, control-plane) | Trivy | - | có |

[`.github/workflows/vuln-scan.yml`](../../.github/workflows/vuln-scan.yml)
chạy Trivy; Trivy được cài bằng
[`scripts/install-trivy.sh`](../../scripts/install-trivy.sh) ở một phiên bản
pin, SHA-256 của gói đã đối chiếu với checksum có chữ ký cosign của Trivy.

- **Gate.** Lỗ hổng đã có bản vá làm job thất bại, ở mọi mức độ. Lỗ hổng
  chưa có bản vá không làm thất bại, nhưng mọi phát hiện đều lên Code
  scanning (tab Security, nhóm `trivy-dependencies` và `trivy-image-*`).
- **Image đã phát hành.** Lần chạy hằng ngày quét image của bản mới nhất.
  Có phát hiện thì mở (hoặc cập nhật) một issue "Known vulnerabilities in
  the v&lt;version&gt; images" gắn nhãn `security`, và lần chạy thất bại để
  hiện trong tab Actions. Lần quét sạch đầu tiên đóng issue. Phát hiện ở
  đây được vá bằng một bản patch.
- **Dependabot** mở pull request cho Go module (`/` và `/tools`), npm, uv,
  GitHub Actions và digest của base image (image: hằng ngày).

## Base image

Image Wolfi của Chainguard được build lại kèm bản vá mỗi ngày và chỉ chứa
những gì binary cần. Chúng thay Debian `bookworm-slim` (gateway: hàng trăm
CVE gói hệ điều hành chưa có bản vá, trong đó một CVE critical ở zlib) và
distroless static (control plane).

| Image | Base | Nội dung |
|---|---|---|
| gateway, gateway-full | `cgr.dev/chainguard/glibc-dynamic` | glibc, libgcc, libstdc++, chứng chỉ CA; ONNX Runtime thêm từ bản phát hành của nó |
| control-plane | `cgr.dev/chainguard/static` | chứng chỉ CA, tzdata, passwd |

Cả hai pin theo digest. Không có shell, trình quản lý gói hay curl, nên các
file triển khai gọi lệnh con của chính binary:

| Trước | Bây giờ |
|---|---|
| `curl -fsS http://localhost:8080/readyz` (HEALTHCHECK, compose, ECS) | `/app/gateway health` (`/app/gateway health /health` chỉ kiểm tra sống) |
| script shell `models-init` (compose, Helm `models-pull`) | `./models init`: tải model mà `DETECTOR_LAYERS` cần; tải lỗi thì cảnh báo, hoặc thoát 1 khi `DETECTOR_REQUIRE_ML=true` / `MODELS_REQUIRED=true` |
| `cp /app/migrations/*.sql /migrations/` (job migration của Helm) | `/app/doctor copy-migrations /migrations /app/migrations` |

Từ 0.4.0, các file compose, Helm chart và module Terraform ECS dùng dạng
mới; image 0.3.x là bản cuối còn shell (thiết lập `gateway.image.shell` của
chart cũ đã bỏ). Một test trong `internal/version` thất bại nếu file triển
khai quay lại dạng shell.

## Khi quét ra lỗ hổng

1. **Đã có bản vá.** Cập nhật dependency hoặc cho pull request của
   Dependabot qua (với base image là bump digest). Nếu nằm trong image đã
   phát hành, ra bản patch trong thời hạn ở SECURITY.md.
2. **Chưa có bản vá.** Vẫn hiển thị trong Code scanning (và trong issue, với
   image đã phát hành). Kiểm tra có ảnh hưởng tới Guard Spec không; bỏ thành
   phần đó nếu không cần.
3. **Không ảnh hưởng tới Guard Spec.** Thêm một statement OpenVEX kèm lý do
   vào [`.vex/guard-spec.openvex.json`](../../.vex/guard-spec.openvex.json);
   mọi lần quét đều đọc tệp này. Ví dụ ở bản tiếng Anh. Statement được xem
   lại mỗi lần phát hành và bỏ đi khi dependency đã cập nhật.

## Kiểm tra một bản cài đang chạy

`doctor` (trong image gateway và control-plane) có check `advisories`: đọc
các security advisory đã công bố của dự án trên GitHub và báo lỗi khi có
advisory ảnh hưởng tới phiên bản đang chạy, kèm phiên bản cần nâng lên.
Request không mang định danh nào của bản cài. Không có internet thì chạy
`doctor -skip advisories`, hoặc đặt `DOCTOR_ADVISORIES_URL` trỏ tới bản sao
của `https://api.github.com/repos/guard-spec/guard-spec/security-advisories?state=published`.

Tự quét một image:

```bash
trivy image ghcr.io/guard-spec/guard-spec-gateway:<version>
```

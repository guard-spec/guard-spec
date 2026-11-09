<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compose cho production với Caddy

> English: [README.md](README.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Một host, Docker Compose, HTTPS. Dành cho startup hoặc một nhóm muốn chạy Guard
Spec trên một VM duy nhất mà không cần Kubernetes. Bản bắt đầu nhanh
([`docker-compose.yml`](../../../docker-compose.yml) ở thư mục gốc của
repository) mở mọi port qua HTTP thường; stack này thì không.

| | Bắt đầu nhanh (thư mục gốc) | Stack này |
|---|---|---|
| Port được mở ra ngoài | 8080, 9090, 18081, 9091 (HTTP thường) | Chỉ 80 và 443 (Caddy) |
| TLS | không có | Caddy: HTTPS tự động (Let's Encrypt, ZeroSSL) hoặc CA nội bộ của Caddy |
| Giới hạn tài nguyên | không có | CPU và bộ nhớ cho từng service, tính theo [docs/sizing.vi.md](../../../docs/sizing.vi.md) |
| Log | Mặc định của Docker (không giới hạn) | json-file, 10 MB x 5 cho mỗi container |
| Tự khởi động lại | không có | `unless-stopped` |
| Health check | gateway | mọi service chạy lâu dài; Caddy chỉ khởi động sau khi gateway và control plane đã healthy |
| Thiếu model | cảnh báo, chạy với L1 | từ chối khởi động (`DETECTOR_REQUIRE_ML=true`) |
| Postgres | mạng mặc định | mạng nội bộ, không có đường ra ngoài |

```text
internet ──443──> caddy ──> gateway:8080        (GATEWAY_HOST)
                        └─> control-plane:8081  (ADMIN_HOST: admin UI at /ui/, API at /v1)
                   edge network                  backend network (internal)
                   gateway, control-plane ─────> postgres
```

## Khởi động

Bạn cần một host có Docker và Compose v2, repository này (hoặc source archive
của một bản phát hành: stack dùng `migrations/` và
`deploy/postgres/set-app-password.sh` trong đó), và hai tên DNS trỏ về host,
với port 80 và 443 đang mở.

```bash
cd deploy/compose/production
cp .env.example .env && chmod 600 .env
# Fill in .env: GATEWAY_HOST, ADMIN_HOST, CADDY_TLS=<your email>, and every
# secret (openssl rand -hex 24 for passwords, openssl rand -hex 32 for
# JWT_SECRET, openssl rand -base64 32 for MFA_ENC_KEY), ADMIN_EMAIL and
# ADMIN_PASSWORD.
docker compose up -d --wait
```

Lần khởi động đầu tiên sẽ kéo các image và model về (khoảng 270 MB; 135 MB nếu
dùng `DETECTOR_LAYERS=l1,l2`), chạy migration, và Caddy lấy certificate cho cả
hai tên. Sau đó:

```bash
curl -s https://$GATEWAY_HOST/readyz      # "layers":["l1","l2","l3"]
open https://$ADMIN_HOST/ui/              # log in with ADMIN_EMAIL / ADMIN_PASSWORD
```

Tạo một API key trong giao diện quản trị (hoặc qua API, như trong phần
[bắt đầu nhanh của README](../../../README.vi.md#bắt-đầu-nhanh), dùng
`https://$ADMIN_HOST/v1` thay cho `http://localhost:18081/v1`), rồi trỏ các
ứng dụng của bạn tới `https://$GATEWAY_HOST/v1`
([docs/integrations.vi.md](../../../docs/integrations.vi.md)).

## Thử nghiệm với CA nội bộ của Caddy

Khi không có DNS công khai (laptop, mạng riêng, CI), hãy để Caddy cấp
certificate từ CA riêng của nó:

```bash
# .env
GATEWAY_HOST=gw.localhost
ADMIN_HOST=admin.localhost
CADDY_TLS=internal
HTTPS_PORT=8443        # if 443 is taken
HTTP_PORT=8480
```

```bash
docker compose up -d --wait
# Either skip verification ...
curl -sk --resolve gw.localhost:8443:127.0.0.1 https://gw.localhost:8443/readyz
# ... or trust Caddy's root certificate.
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
curl -s --cacert caddy-root.crt --resolve gw.localhost:8443:127.0.0.1 https://gw.localhost:8443/readyz
```

Khi đó client cần có `caddy-root.crt` (Python: `SSL_CERT_FILE` hoặc
`REQUESTS_CA_BUNDLE`; Node: `NODE_EXTRA_CA_CERTS`). Root certificate nằm trong
volume `caddy_data` và được `scripts/backup.sh` sao lưu. Nếu dùng port khác
443, lệnh chuyển hướng HTTP sang HTTPS của Caddy vẫn trỏ về port 443; hãy gọi
thẳng vào port HTTPS.

## Cấu hình

Mọi thứ nằm trong `.env` ([`.env.example`](.env.example) liệt kê đầy đủ):

| Biến | Mặc định | Ghi chú |
|---|---|---|
| `GATEWAY_HOST`, `ADMIN_HOST` | bắt buộc | Hai tên riêng; control plane không được phục vụ trên tên của gateway |
| `CADDY_TLS` | bắt buộc | Email của bạn (ACME) hoặc `internal` |
| `ADMIN_ALLOW` | `0.0.0.0/0 ::/0` | Các dải địa chỉ client được phép vào `ADMIN_HOST`, ví dụ VPN của bạn. Cần Docker chuyển đúng địa chỉ thật của client (mặc định trên Linux; Docker Desktop thì không) |
| `DETECTOR_LAYERS` | `l1,l2,l3` | `l1,l2` là chế độ nhẹ ([docs/sizing.vi.md](../../../docs/sizing.vi.md)) |
| `GATEWAY_CPUS`, `GATEWAY_MEMORY` | `2`, `2g` | Mức đỉnh đo được: detector đầy đủ 0.9 GiB, chế độ nhẹ 0.5 GiB |
| `INFERENCE_MAX_CONCURRENCY`, `INFERENCE_INTRA_OP_THREADS` | `2`, `1` | Số lượt chạy model cùng lúc x số thread mỗi lượt; giữ tích này không vượt quá `GATEWAY_CPUS` |
| `MAX_SCAN_TOKENS`, `INFERENCE_LARGE_MAX_CONCURRENCY`, `LARGE_SCAN_QUEUE_TIMEOUT` | không đặt (giới hạn hiện tại), `GATEWAY_CPUS` / 4 (ít nhất 1), `30s` | Input lớn: trần token mở đường dài, số request lớn được quét cùng lúc, và thời gian chờ trước khi nhận 429. Xem [Input lớn](../../../README.vi.md#input-lớn) |
| `CONTROL_PLANE_CPUS`, `CONTROL_PLANE_MEMORY` | `1`, `256m` | |
| `POSTGRES_CPUS`, `POSTGRES_MEMORY` | `2`, `1g` | |
| `CADDY_CPUS`, `CADDY_MEMORY` | `1`, `256m` | |
| `LOG_MAX_SIZE`, `LOG_MAX_FILE` | `10m`, `5` | Cho mỗi container |
| `EDGE_SUBNET` | `172.30.89.0/24` | Control plane tin `X-Forwarded-For` đến từ dải này (Caddy); đổi nếu nó trùng với mạng của bạn |
| `GUARDSPEC_VERSION` | `0.4.1` | Tag của image ([docs/upgrade.vi.md](../../../docs/upgrade.vi.md)) |

`UPSTREAM_KEY_ORGS` không có giá trị mặc định ở đây (bản bắt đầu nhanh cho mọi
org dùng `UPSTREAM_KEY_MAIN`), và `UPSTREAM_ALLOW_PRIVATE` là `false`: hãy đặt
chúng một cách có chủ đích, như [phần Routing của README](../../../README.md#routing)
giải thích.

Metrics (gateway `:9090`, control plane `:9091`) không được mở ra ngoài. Hãy
chạy Prometheus trên mạng `edge` (`<project>_edge`) và scrape
`gateway:9090` và `control-plane:9091`.

## Vận hành

- Backup: chạy `scripts/backup.sh -f deploy/compose/production/docker-compose.yml`
  từ thư mục gốc của repository, khôi phục bằng `scripts/restore.sh`
  ([docs/upgrade.md](../../../docs/upgrade.md#backups)).
- Nâng cấp và rollback: [docs/upgrade.vi.md](../../../docs/upgrade.vi.md).
- Định cỡ tài nguyên: [docs/sizing.vi.md](../../../docs/sizing.vi.md).
- Dùng database managed thay cho service `postgres`:
  [docs/managed-postgres.vi.md](../../../docs/managed-postgres.vi.md).
- Log: `docker compose logs -f gateway`; Caddy ghi một dòng JSON cho mỗi
  request (không ghi body).

## Những gì đã được kiểm tra

Trên một máy Mac Apple Silicon (arm64) với Docker Desktop, dùng
`CADDY_TLS=internal`: stack khởi động healthy và chỉ có Caddy mở port ra
ngoài; `/readyz` báo `l1,l2,l3` qua HTTPS, được xác minh bằng root certificate
đã export từ Caddy; một prompt vô hại đi qua (200), một injection bị chặn
(400), giao diện quản trị tải được; một bản backup khôi phục vào một compose
project mới vẫn giữ nguyên organization, user, API key, policy, các dòng audit
và CA của Caddy. HTTPS tự động với một ACME CA công khai chưa được chạy thử
(vì cần DNS công khai); Caddyfile được `caddy adapt` chuyển thành một ACME
policy cho cả hai tên.

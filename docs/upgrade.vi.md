<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nâng cấp, rollback và sao lưu

> English: [upgrade.md](upgrade.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Áp dụng cho các stack compose: bản quick start (`docker-compose.yml` ở thư mục
gốc repository) và
[compose production](../deploy/compose/production/README.vi.md). Kubernetes:
[docs/deploy/on-premise.md](deploy/on-premise.md#upgrade-and-rollback-1).

Có ba thứ có phiên bản, và mỗi thứ rollback độc lập:

| Thành phần | Ghim bằng | Thay đổi khi nâng cấp | Rollback |
|---|---|---|---|
| Image (gateway, control plane) | `GUARDSPEC_VERSION` trong `.env` | Code | Tag trước đó |
| Schema database | `migrations/` của bản checkout; được job `migrate` áp dụng ở mỗi lần `up` | Chỉ tiến lên | Khôi phục bản backup trước khi nâng cấp |
| Model | `models/manifest.yaml` của mỗi image, hoặc `L2_MODEL` / `L3_MODEL` trong `.env` | Một release có thể khuyến nghị model mới hơn | `L2_MODEL=name@old-version` |

Trước 1.0, một phiên bản minor có thể thay đổi schema và cấu hình: hãy đọc
[CHANGELOG](../CHANGELOG.md) của mọi phiên bản bạn bỏ qua.

## Sao lưu

`scripts/backup.sh` lưu những gì cần để khôi phục, trong khi stack vẫn chạy:

```bash
scripts/backup.sh                                                     # quick start
scripts/backup.sh -f deploy/compose/production/docker-compose.yml    # production
# backup: done: backups/guardspec-20261106T060839Z
```

| File | Nội dung | Tại sao quan trọng |
|---|---|---|
| `guardspec.dump` | `pg_dump -Fc` của database: organization, user, API key (dạng hash), policy, upstream, alert rule, các dòng audit, `schema_migrations` | Dữ liệu |
| `guardspec.env` | File `.env` mà stack đã chạy cùng | `POSTGRES_PASSWORD` và `GUARDSPEC_APP_PASSWORD`; `JWT_SECRET` (thiếu nó mọi phiên đăng nhập đều mất hiệu lực; người dùng phải đăng nhập lại); **`MFA_ENC_KEY`, khóa duy nhất mã hóa dữ liệu lưu trữ** (secret TOTP 2FA, AES-256-GCM): thiếu nó phải reset 2FA của mọi người dùng; và các secret mà database chỉ ghi tên chứ không giữ giá trị: `UPSTREAM_KEY_*` / `UPSTREAM_LLM_KEY` (upstream `api_key_env`), `OIDC_SECRET_*` (SSO `client_secret_env`), secret của kênh cảnh báo (`secret_env`), SMTP và token bot |
| `caddy-data.tgz` | `/data` của Caddy (chỉ có ở compose production) | Certificate, tài khoản ACME, và với `CADDY_TLS=internal` là root CA mà các client của bạn tin cậy |
| `MANIFEST` | Thời điểm, image, phiên bản migration, số dòng, SHA-256 của từng file | Cho biết bản backup là gì, và dùng để kiểm tra toàn vẹn khi khôi phục |

Cố ý không bao gồm: model (được tải lại và kiểm tra với manifest, hoặc ghim
bằng `L2_MODEL`), image (tải theo tag), và các secret giữ ngoài `.env` (trong
secret manager: hãy sao lưu chúng ở đó).

Thư mục được tạo với mode 700 và chứa mọi secret: hãy mã hóa nó (`age`,
`gpg`, tính năng mã hóa của công cụ backup) và giữ nó ngoài host. API key được
lưu dưới dạng hash SHA-256, nên bản backup không thể làm lộ chúng; hash mật
khẩu dùng bcrypt.

Lên lịch bằng cron hoặc systemd timer, ví dụ hằng ngày:

```cron
15 3 * * * cd /opt/guard-spec && scripts/backup.sh -f deploy/compose/production/docker-compose.yml -o /var/backups/guardspec/$(date +\%F) && find /var/backups/guardspec -mindepth 1 -maxdepth 1 -mtime +14 -exec rm -rf {} +
```

### Khôi phục

Chỉ khôi phục vào database trống (host mới, compose project mới, hoặc sau
`docker compose down -v`); database đã có bảng sẽ bị từ chối:

```bash
scripts/restore.sh -f deploy/compose/production/docker-compose.yml backups/guardspec-20261106T060839Z
```

Script kiểm tra SHA-256 của bản dump, ghi `.env` của bản backup nếu chưa có
(và từ chối nếu `.env` hiện có mang `MFA_ENC_KEY` khác), khởi động Postgres,
tạo role toàn cluster `guardspec_app` (bản dump database không mang theo
role), chạy `pg_restore`, đưa dữ liệu Caddy về chỗ cũ, rồi khởi động stack:
`migrate` áp dụng các migration mới hơn bản dump và `db-roles` đặt mật khẩu
`guardspec_app` từ `.env`. Đăng nhập, 2FA, API key và CA nội bộ vẫn hoạt
động.

*Đã kiểm tra* ngày 2026-11-06 (arm64, Docker Desktop): bản backup của một stack
compose production (1 organization, 1 user, 1 API key, 1 policy, 26,004 dòng
audit) được khôi phục vào một compose project riêng. Checksum của
organization, user, API key, policy và các dòng audit đều khớp; mật khẩu
admin và API key cũ vẫn dùng được; một injection bị chặn và một prompt vô hại
được cho qua trên HTTPS, xác thực bằng root Caddy ban đầu.

Database managed: [docs/managed-postgres.md](managed-postgres.md#backups).

## Nâng cấp

```bash
scripts/backup.sh [-f ...]                          # 1. a backup to roll back to
git fetch --tags && git checkout v<new-version>     # 2. new migrations/ and compose files
# 3. .env: GUARDSPEC_VERSION=<new-version>; compare .env.example for new settings
docker compose [-f ...] pull                        # 4. images first, so the switch is short
docker compose [-f ...] up -d --wait                # 5. migrate and db-roles run before the services
curl -s localhost:8080/readyz | jq .detector        # 6. or https://<GATEWAY_HOST>/readyz
```

- Bước 2 quan trọng: job `migrate` áp dụng thư mục `migrations/` trong bản
  checkout của bạn, nên checkout và `GUARDSPEC_VERSION` phải cùng một release.
  Một archive mã nguồn của release cũng dùng được như một bản checkout.
- Trong bước 5 gateway khởi động lại; các request đang xử lý sẽ lỗi và client
  thử lại. Với một host thì không tránh được điều này; để không có downtime,
  hãy chạy nhiều replica gateway sau một load balancer (Kubernetes, Helm
  chart).
- Model: nếu image mới khuyến nghị một phiên bản model mới, `models-init` tải
  nó trước khi gateway khởi động (với `DETECTOR_REQUIRE_ML=true`, mặc định
  của production, một lần tải lỗi sẽ dừng `up` trước khi gateway mới khởi
  động). Khi đã ghim `L2_MODEL` / `L3_MODEL`, gateway giữ phiên bản đã ghim.
- Phiên bản classifier mới: để thử trước khi chuyển, giữ `L2_MODEL` đã ghim
  và đặt `SHADOW_L2_MODEL=guardspec-classifier@<new>`. Nó chấm điểm cùng lưu
  lượng nhưng không ra quyết định; so sánh trong giao diện quản trị
  (**Models**). Sau đó chuyển mà không cần khởi động lại bằng
  `POST /admin/models/reload` với
  `{"l2_model":"guardspec-classifier@<new>","shadow_l2_model":"off"}`
  (`GATEWAY_ADMIN_TOKEN`), và đặt `L2_MODEL` trong `.env` cho lần khởi động
  sau (hoặc đặt nó rồi chạy `up -d gateway`, lệnh này sẽ khởi động lại). Một
  lần reload kiểm tra SHA-256 của các file và giữ model đang chạy nếu có gì
  lỗi; xem
  [README, Shadow mode and model reload](../README.md#shadow-mode-and-model-reload).
- Kiểm tra sau khi nâng cấp: `/readyz` liệt kê đúng các lớp bạn mong đợi, giao
  diện quản trị tải được, một injection đã biết bị chặn
  ([Bắt đầu nhanh trong README](../README.vi.md#bắt-đầu-nhanh)).
- Với image từ 0.2.0, chạy thêm `doctor` bên trong gateway:
  `docker compose [-f ...] exec gateway /app/doctor`. Nó kiểm tra database,
  phiên bản migration có khớp với `migrations/` của image hay không, các file
  model so với SHA-256 trong manifest, những lớp nào sẽ được nạp, upstream và
  các thiết lập bảo mật; exit code 1 nghĩa là có một bước kiểm tra lỗi
  (`-strict` coi cả cảnh báo là lỗi, `-json` dùng cho script). Xem
  [README, Kubernetes](../README.md#kubernetes).

### Ghi chú migration

Các migration của một bản làm gì ngoài việc thêm bảng, và cần kiểm tra gì sau
đó. [CHANGELOG](../CHANGELOG.md) có đầy đủ ghi chú nâng cấp của từng phiên bản.

- **026 (phiên bản chính sách).** Thêm `policies.log_only` và bảng
  `policy_versions`, và ghi một phiên bản cho mỗi chính sách đang có (trạng
  thái lúc nâng cấp) để lần sửa đầu tiên sau nâng cấp có thể khôi phục. Xuống
  (down): lịch sử bị xóa và chính sách chỉ ghi log trở thành chính sách thật,
  nên hãy tắt các chính sách đó trước.
- **027 (phê duyệt hai người).** Thêm bảng `approval_requests` và hai cột
  `org_security`; tắt với mọi tổ chức. Down: yêu cầu đang chờ bị xóa.
- **028 (chính sách khóa API).** Thay hàm `lookup_api_key` để trả thêm địa chỉ
  được phép của khóa. Gateway trước 0.7.0 vẫn chạy với hàm mới (chỉ đọc hai cột
  đầu); gateway 0.7.0 cần migration này, nên hãy áp dụng trước khi gateway khởi
  động, như job `migrate` của compose vẫn làm. Đặt `TRUSTED_PROXIES` cho
  **gateway** khi nó đứng sau reverse proxy và bạn dùng `allowed_cidrs`: nếu
  không, địa chỉ của proxy sẽ được coi là client. Down: khóa giới hạn địa chỉ
  dùng được từ mọi nơi trở lại; hãy thu hồi trước nếu điều đó quan trọng. Hạn
  do xoay khóa hoặc thời hạn tối đa đặt ra vẫn giữ nguyên.
- **029 (phê duyệt nhất quán).** Thêm trạng thái `cancelled`, một chỉ mục duy
  nhất một phần để mỗi tổ chức, loại và đối tượng chỉ có một yêu cầu đang chờ,
  và cho quản trị viên hệ thống đọc các yêu cầu xóa tổ chức đang chờ. Migration
  hủy các yêu cầu `policy.delete` đang chờ (xóa chính sách không còn cần duyệt;
  chỉ xóa được chính sách đã tắt) và, nếu một thay đổi đang chờ hai lần, hủy mọi
  yêu cầu trừ yêu cầu cũ nhất. Sau migration: client API và tệp cấu hình xóa
  chính sách **đang bật** sẽ nhận 409 `policy_enabled` (422 với tệp): hãy tắt
  trước. Xóa tổ chức luôn thành yêu cầu do một owner khác hoặc quản trị viên hệ
  thống duyệt, dù phê duyệt hai người bật hay tắt. Down: yêu cầu đã hủy được
  coi là hết hạn và yêu cầu trùng lại được phép.
- **030 (thiết lập đầu vào).** Thêm `org_input_settings` (một dòng cho mỗi tổ
  chức tự đặt chế độ đầu vào, giới hạn token, loại file và cách xử lý file
  không đọc được) và loại phê duyệt `input_settings.loosen`. Sau migration
  không tổ chức nào có dòng này, nên mọi tổ chức giữ hành vi của instance
  (`PDF_EXTRACT`, `UNSCANNED_PARTS`, `MAX_SCAN_TOKENS`) cho đến khi admin đặt
  thiết lập. Gateway 0.7.0 đọc bảng này cùng thiết lập bảo vệ của mỗi request:
  hãy chạy migration trước khi gateway khởi động, nếu không request sẽ bị từ
  chối an toàn với 503. Đặt `GATEWAY_URL` cho control plane để nó kiểm tra
  `max_input_tokens` theo `MAX_SCAN_TOKENS` của gateway (không đặt thì giới
  hạn là 40.000). Down: thiết lập và các yêu cầu nới lỏng đang chờ bị xóa, mọi
  tổ chức quay về hành vi của instance.

## Rollback

### Image, không đổi schema

Khi release bạn rời khỏi không thêm migration nào (so sánh `migrations/` của
hai tag, hoặc phiên bản migration trong `MANIFEST` với phiên bản mới):

```bash
git checkout v<old-version>
# .env: GUARDSPEC_VERSION=<old-version>
docker compose [-f ...] up -d --wait
```

### Image và schema

Schema mới hơn với code cũ hơn không được hỗ trợ, và các migration
`*.down.sql` xóa những gì phiên bản mới đã thêm, kể cả dữ liệu; đó không phải
đường đi đã được kiểm thử. Thay vào đó, hãy khôi phục bản backup tạo trước khi
nâng cấp:

```bash
docker compose [-f ...] down -v      # removes the upgraded database: keep the backup safe first
git checkout v<old-version>
# .env: GUARDSPEC_VERSION=<old-version> (restore.sh keeps an existing .env)
scripts/restore.sh [-f ...] backups/guardspec-<before-upgrade>
```

Các dòng audit ghi giữa lúc backup và lúc rollback sẽ bị mất. Muốn giữ chúng,
hãy export trước (`GET /v1/organizations/{id}/requests`, hoặc
`pg_dump -t requests`).

`down -v` cũng xóa volume model của compose production (sẽ được tải lại) và
dữ liệu của Caddy (được khôi phục từ bản backup).

### Chỉ model

Không đổi image hay schema: tải phiên bản cũ và ghim nó.

```bash
docker compose [-f ...] --profile models run --rm models-pull guardspec-classifier@<old>
# .env: L2_MODEL=guardspec-classifier@<old>
docker compose [-f ...] up -d gateway
curl -s localhost:8080/readyz | jq .detector.l2_model
```

Không cần khởi động lại: giữ phần ghim trong `.env` cho lần khởi động sau, và
nạp lại gateway đang chạy bằng `POST /admin/models/reload` với
`{"l2_model":"guardspec-classifier@<old>"}` (cần `GATEWAY_ADMIN_TOKEN`).
SIGHUP nạp lại các model mà gateway đang nhắm tới, chứ không đọc `.env` đã
thay đổi.

Chi tiết, embedder L3 và cài đặt air-gapped:
[docs/models.md](models.md#rolling-back).

### Nâng cấp thất bại

- `migrate` thoát với mã khác 0: các service không khởi động (chúng chờ nó).
  `docker compose logs migrate` cho biết migration nào. Một migration lỗi để
  lại `schema_migrations.dirty = true`; hãy sửa nguyên nhân, rồi khôi phục
  bản backup thay vì ép phiên bản.
- `models-init` lỗi: đang offline, hoặc mirror thiếu phiên bản mới. Đặt
  `MODELS_MIRROR`, hoặc ghim `L2_MODEL` / `L3_MODEL` trước đó, rồi `up` lại.
- Gateway không healthy: xem `docker compose logs gateway`; với
  `DETECTOR_REQUIRE_ML=true`, thiếu model sẽ làm gateway dừng ngay khi khởi
  động, đây là chủ ý thiết kế.

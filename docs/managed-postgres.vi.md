<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# PostgreSQL được quản lý: RDS, Cloud SQL, Neon, Supabase

> English: [managed-postgres.md](managed-postgres.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

> **Trạng thái: tài liệu tham khảo, các maintainer chưa kiểm chứng trên các
> nhà cung cấp này.** Cộng đồng đã thử: chưa. Nếu bạn chạy Guard Spec trên một
> trong số đó, hãy mở một
> [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) hoặc một
> pull request ghi lại điều gì chạy được và điều gì không; rất hoan nghênh
> đóng góp của bạn. Xem [CONTRIBUTING.md](../CONTRIBUTING.md).

Các file compose và CI dùng PostgreSQL 17; các phiên bản cũ hơn chưa được thử.
Nhà cung cấp nào cũng sẽ dùng được nếu cho bạn các role và extension liệt kê
bên dưới. Trang này nói về những gì migration cần, connection string và TLS,
và cách chạy [compose production](../deploy/compose/production/README.vi.md)
mà không cần dịch vụ `postgres` riêng của nó. Với Kubernetes, các bước cho
database cũng giống vậy; xem [docs/deploy/](deploy/README.vi.md).

**Những gì maintainer đã kiểm tra** (2026-11-06, trên máy local, không phải
trên nhà cung cấp nào): một container PostgreSQL 17 đóng vai database được
quản lý, trong đó owner role `gsowner` **không** phải superuser nhưng có
`CREATEROLE` và sở hữu database, giống như trên RDS, Cloud SQL, Neon và
Supabase. Chạy với role đó, mọi migration đều áp dụng thành công,
`set-app-password.sh` chạy được, compose production cùng
`managed-postgres.yml` khởi động ở trạng thái healthy, một prompt injection
bị chặn và một prompt vô hại đi qua được qua HTTPS. Một database thứ hai trên
cùng server thất bại ở migration 004 với lỗi
`role "guardspec_app" already exists` (xem bên dưới). TLS tới database không
nằm trong bài kiểm tra đó.

## Database cần những gì

| Yêu cầu | Lý do | Ghi chú |
|---|---|---|
| Một **owner role** chạy các migration và sở hữu mọi bảng | Các dịch vụ chạy dưới role `guardspec_app`, role này không sở hữu các bảng nên row-level security áp dụng với nó. Một vài hàm `SECURITY DEFINER` (tra cứu API key, lời mời, cảnh báo) chạy dưới quyền owner và phải bỏ qua được RLS, điều mà chủ sở hữu bảng làm được. | User admin của nhà cung cấp, hoặc một role bạn tạo riêng cho Guard Spec. Không phải superuser. |
| `CREATEROLE` cho owner role | Migration 004 chạy `CREATE ROLE guardspec_app LOGIN`; migration 005 và `set-app-password.sh` chạy `ALTER ROLE guardspec_app ...` | Trên PostgreSQL 16 trở lên, role đã tạo `guardspec_app` vẫn giữ quyền thay đổi nó. |
| Extension `pgcrypto` và `pg_trgm` | Migration 001 (`CREATE EXTENSION IF NOT EXISTS`) | Cả hai đều là extension "trusted": chủ sở hữu database có thể tạo chúng mà không cần là superuser. Cả bốn nhà cung cấp đều có. |
| Schema `public`, owner ghi được | Các bảng, hàm và `schema_migrations` nằm ở đó | Trên PostgreSQL 15+, chỉ chủ sở hữu database ghi được vào `public`, đúng như bạn cần. |

**`guardspec_app` có phạm vi toàn cluster.** Role thuộc về cả server
(instance, cluster), không thuộc về một database riêng, và migration 004 tạo
role với một tên cố định. Vì vậy:

- mỗi server chỉ một bản cài Guard Spec: bản cài thứ hai trên cùng instance
  (ví dụ một database staging đặt cạnh production) sẽ thất bại ở migration 004
  với lỗi `role "guardspec_app" already exists`. Hãy cho staging một instance,
  project Neon hoặc project Supabase riêng;
- khôi phục một bản dump vào instance mới cần tạo role trước (`pg_dump` của
  một database không mang theo role): chạy `CREATE ROLE guardspec_app LOGIN;`
  dưới owner role, rồi `pg_restore`. `scripts/restore.sh` làm việc này cho
  compose.

## Connection string và TLS

Các dịch vụ đọc `DATABASE_URL` và lấy mật khẩu từ `PGPASSWORD` (compose truyền
`GUARDSPEC_APP_PASSWORD` vào đó), nên URL không chứa secret nào:

```text
DATABASE_URL=postgres://guardspec_app@<host>:5432/guardspec?sslmode=verify-full
```

Gateway và control plane dùng pgx, thư viện này nhận các tham số libpq
`sslmode` (`require`, `verify-ca`, `verify-full`), `sslrootcert`, `sslcert`
và `sslkey`. Với `verify-full` mà không có `sslrootcert`, bộ CA của hệ thống
được dùng: cách này chạy được khi certificate của nhà cung cấp nối chuỗi tới
một CA công khai (Neon, theo tài liệu của họ), và không chạy được khi họ dùng
CA riêng (RDS, Cloud SQL, Supabase); khi đó bạn mount file CA của họ và chỉ
định nó:

```yaml
# deploy/compose/production/managed-postgres.yml, under gateway and control-plane:
    volumes:
      - ./db-ca.pem:/etc/guardspec/db-ca.pem:ro
# .env:
# DATABASE_URL=postgres://guardspec_app@<host>:5432/guardspec?sslmode=verify-full&sslrootcert=/etc/guardspec/db-ca.pem
```

`sslmode=require` có mã hoá nhưng không kiểm tra danh tính của server; chỉ
dùng nó lúc mới bắt đầu.

## Ghi chú theo nhà cung cấp

### Amazon RDS for PostgreSQL

- Owner: master user (thành viên của `rds_superuser`, có `CREATEROLE`), hoặc
  một role riêng do master user tạo: `CREATE ROLE gsowner LOGIN CREATEROLE
  PASSWORD '...'; CREATE DATABASE guardspec OWNER gsowner;`
- TLS: RDS for PostgreSQL 15 trở lên đặt `rds.force_ssl=1`. Tải CA bundle của
  region (`global-bundle.pem` trong tài liệu RDS) và dùng
  `sslmode=verify-full&sslrootcert=...`.
- Host: endpoint của instance, `<name>.<id>.<region>.rds.amazonaws.com`.
  Nếu đi qua RDS Proxy, xem phần "Pooler" bên dưới.
- Thêm: [docs/deploy/aws.md](deploy/aws.md).

### Google Cloud SQL for PostgreSQL

- Owner: user `postgres` (thành viên của `cloudsqlsuperuser`, có
  `CREATEROLE`), hoặc một user bạn tạo trong console hay bằng
  `gcloud sql users create` rồi đặt làm chủ sở hữu database.
- TLS: hoặc kết nối tới IP của instance với certificate CA của server lấy từ
  console (`sslmode=verify-ca` với file đó: certificate server của Cloud SQL
  không phải lúc nào cũng chứa tên host), hoặc chạy Cloud SQL Auth Proxy cạnh
  các dịch vụ và kết nối tới nó với `sslmode=disable` (proxy lo phần mã hoá).
- Thêm: [docs/deploy/gcp.md](deploy/gcp.md).

### Neon

- Owner: role mà Neon tạo cùng project (thành viên của `neon_superuser`, có
  `CREATEROLE`).
- TLS: bắt buộc; certificate nối chuỗi tới một CA công khai, nên
  `sslmode=verify-full` chạy được mà không cần `sslrootcert`.
- Dùng endpoint **direct** (host không có `-pooler`) cho migration và cho các
  dịch vụ (xem "Pooler").
- Scale-to-zero: query đầu tiên sau một khoảng thời gian rảnh phải chờ compute
  khởi động. Với production, hãy tắt auto-suspend hoặc giữ một kích thước
  compute tối thiểu, nếu không các request đầu tiên sau lúc yên ắng sẽ chậm.

### Supabase

- Owner: user `postgres` (có `CREATEROLE`, không phải superuser).
- `pgcrypto` đã được cài sẵn (trong schema `extensions`); migration 001 để
  nguyên nó ở đó và tạo `pg_trgm`.
- Kết nối: kết nối trực tiếp (`db.<project>.supabase.co:5432`) hoặc pooler ở
  session mode (cổng 5432 trên host pooler); không dùng transaction mode (cổng
  6543), xem "Pooler". Host trực tiếp có thể chỉ có IPv6, thứ mà mạng Docker
  thường không có; session pooler thì có IPv4.
- TLS: Supabase dùng CA riêng (tải về từ phần cài đặt database của project);
  `sslmode=verify-full&sslrootcert=...`.
- Guard Spec chỉ cần database: Supabase API, auth và storage không được dùng.
  Đừng để các bảng của Guard Spec lộ ra qua Supabase REST API: chúng thuộc
  owner role và nằm trong `public`, schema mà API phục vụ theo mặc định, nên
  hãy kiểm tra các schema mà API đang mở ra.

### Pooler

Các dịch vụ tự giữ connection pool riêng và dùng prepared statement cùng các
transaction có đặt `app.org_id` cho row-level security. Hãy kết nối chúng
trực tiếp, hoặc qua một pooler ở **session** mode. Pooling ở transaction mode
(PgBouncer `pool_mode=transaction`, Supabase cổng 6543, hành vi pinning của
RDS Proxy) chưa được thử và nhiều khả năng sẽ làm hỏng prepared statement hoặc
các thiết lập theo từng transaction.

## Chạy migration

Chạy dưới owner role, từ một bản checkout của đúng release bạn triển khai (thư
mục `migrations/` phải khớp với phiên bản của các image):

```bash
export DB_HOST=<host>
export OWNER=<owner role>
export PGPASSWORD=<owner password>
export PARAMS='sslmode=verify-full'   # add &sslrootcert=/ca/<file> with -v "$PWD/<file>:/ca/<file>:ro"

docker run --rm -e PGPASSWORD -v "$PWD/migrations:/migrations:ro" \
  migrate/migrate:v4.20.1 -path=/migrations \
  -database "postgres://$OWNER@$DB_HOST:5432/guardspec?$PARAMS" up
```

Sau đó đặt mật khẩu cho role ứng dụng (sau các migration nó chưa có mật khẩu;
chạy lại lệnh này để xoay vòng mật khẩu):

```bash
export GUARDSPEC_APP_PASSWORD=<openssl rand -hex 24>
docker run --rm -e PGHOST="$DB_HOST" -e PGUSER="$OWNER" -e PGDATABASE=guardspec \
  -e PGPASSWORD -e PGSSLMODE=verify-full -e GUARDSPEC_APP_PASSWORD \
  -v "$PWD/deploy/postgres/set-app-password.sh:/set-app-password.sh:ro" \
  postgres:17.11-alpine sh /set-app-password.sh
# guardspec_app password set
```

`set-app-password.sh` từ chối mật khẩu yếu hoặc mật khẩu mặc định (cả mật
khẩu của owner trong `PGPASSWORD`). Chạy lại cả hai bước mỗi lần nâng cấp,
trước khi các image mới khởi động ([docs/upgrade.vi.md](upgrade.vi.md)); công
cụ migrate chỉ áp dụng những gì mới.

## Compose production không kèm database

[`deploy/compose/production/managed-postgres.yml`](../deploy/compose/production/managed-postgres.yml)
đưa các dịch vụ `postgres`, `migrate` và `db-roles` vào sau một profile và trỏ
gateway cùng control plane tới `DATABASE_URL`:

```bash
cd deploy/compose/production
# .env: DATABASE_URL=..., GUARDSPEC_APP_PASSWORD (the one set above), and
# POSTGRES_PASSWORD set to any long value (unused, but required by the file)
docker compose -f docker-compose.yml -f managed-postgres.yml up -d --wait
```

Gateway và control plane nằm trên mạng `edge`, mạng này có đường ra ngoài;
database phải chấp nhận kết nối từ địa chỉ của máy host (security group,
authorized networks, IP allow list).

## Sao lưu

`scripts/backup.sh` dump dịch vụ `postgres` của compose nên không dùng được ở
đây. Hãy dùng backup tự động và point-in-time recovery của nhà cung cấp, và
giữ `.env` cẩn thận như vậy (nhất là `MFA_ENC_KEY`: các secret 2FA trong
database được mã hoá bằng nó). Nên có thêm một bản dump logic:

```bash
docker run --rm -e PGPASSWORD postgres:17.11-alpine \
  pg_dump -Fc "postgres://$OWNER@$DB_HOST:5432/guardspec?$PARAMS" > guardspec.dump
```

Khôi phục một snapshot vào instance mới sẽ mang theo các role; khôi phục một
bản dump thì không (tạo `guardspec_app` trước, như ở trên, rồi chạy
`set-app-password.sh`).

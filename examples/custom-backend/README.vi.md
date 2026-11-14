<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Backend tùy chỉnh: gateway đứng trước API JSON của bạn

> English: [README.md](README.md).

[`sample_backend.py`](sample_backend.py) là một API tìm kiếm nhỏ, kiểu dịch
vụ mà tổ chức đặt trước một mô hình: `POST /search` nhận
`{"query": "...", "filters": [...]}` và trả về kết quả có đoạn trích chứa một
địa chỉ e-mail. [`demo.py`](demo.py) gọi nó qua gateway tại
`/v1/backend/search/search` và kiểm tra rằng:

- yêu cầu sạch tới backend **nguyên từng byte** (`forwarded unchanged: yes`);
- e-mail trong phản hồi bị bộ lọc đầu ra che đi (`redacted: ...`);
- injection trong `query` bị chặn (`blocked: content_filter`) và số yêu cầu
  backend nhận được không đổi (`not reached: ...`);
- đường dẫn ngoài các tiền tố cho phép bị từ chối (`refused path: 403 path_not_allowed`).

Cả hai chỉ dùng thư viện chuẩn của Python 3. Cách backend tùy chỉnh hoạt
động: [docs/integrations.vi.md](../../docs/integrations.vi.md#backend-tùy-chỉnh).

## Chạy thử

Với gateway dùng thử của [`examples/dev`](../README.vi.md), script này khởi
động backend mẫu và đăng ký nó làm backend tùy chỉnh `search` của tổ chức
phát triển:

```bash
examples/dev/start.sh
set -a; . examples/dev/.state/env; set +a
python3 examples/custom-backend/demo.py
examples/dev/stop.sh
```

Với gateway của bạn: chạy backend ở nơi gateway truy cập được (địa chỉ nội
bộ cần đặt `UPSTREAM_ALLOW_PRIVATE=true` cho gateway), thêm một nhà cung cấp
loại **Backend tùy chỉnh** tên `search` trong giao diện quản trị (Nhà cung cấp
mô hình) với base URL `http://<backend-host>:18198`, tiền tố đường dẫn
`/search`, phương thức `POST`, trường yêu cầu `$.query` và `$.filters[*]`,
trường phản hồi `$.results[*].snippet`, rồi chạy:

```bash
python3 examples/custom-backend/sample_backend.py --host 0.0.0.0 --port 18198 &
GUARDSPEC_BASE_URL=http://localhost:8080 GUARDSPEC_API_KEY=gs_... \
GUARDSPEC_BACKEND_URL=http://127.0.0.1:18198 python3 examples/custom-backend/demo.py
```

`GUARDSPEC_BACKEND_URL` là chính backend: demo đọc số yêu cầu từ
`GET /_stats`, đường dẫn mà gateway không chuyển tiếp.

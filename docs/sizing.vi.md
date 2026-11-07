<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Định cỡ tài nguyên

> English: [sizing.md](sizing.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Guard Spec cần bao nhiêu CPU, bộ nhớ và ổ đĩa, tuỳ theo các lớp phát hiện bạn
bật. Gateway chiếm phần lớn: bộ nhớ của nó phụ thuộc vào các model được nạp,
còn CPU phụ thuộc vào số prompt mỗi giây mà các lớp model phải chấm điểm.
Control plane và Postgres nhỏ hơn nhiều.

## Chọn lớp phát hiện

`DETECTOR_LAYERS` chọn các lớp (một biến duy nhất, trong `.env`):

| Chế độ | `DETECTOR_LAYERS` | Model được tải về | Dùng khi |
|---|---|---|---|
| Đầy đủ (mặc định) | `l1,l2,l3` | classifier + embedder e5, khoảng 270 MB | Production còn dư RAM; L3 so khớp với các exemplar riêng của tổ chức và bắt thêm được các tấn công đã được diễn đạt lại |
| Nhẹ | `l1,l2` | chỉ classifier, khoảng 135 MB | Laptop, VM nhỏ, dùng cá nhân; tốn khoảng một nửa bộ nhớ và throughput cao gấp 2 đến 3 lần chế độ đầy đủ |
| Chỉ luật | `l1` | không có | Máy rất nhỏ, hoặc khi false positive (chặn nhầm) gây thiệt hại nhiều hơn tấn công bị bỏ sót; yếu hơn nhiều với các câu diễn đạt lại |

```bash
# quick start in light mode (writes DETECTOR_LAYERS=l1,l2 into the new .env)
DETECTOR_LAYERS=l1,l2 scripts/quickstart.sh
# an existing stack: set DETECTOR_LAYERS=l1,l2 in .env, then
docker compose -f docker-compose.yml up -d
```

`models-init` chỉ tải những model mà các lớp đã chọn cần, và `/readyz` cho
biết các lớp đang chạy (`"layers":["l1","l2"]`). Mỗi lớp phát hiện gì và được
kết hợp ra sao: xem README, phần [Model](../README.vi.md#model) và
[Benchmark](../README.vi.md#benchmark).

## Mức dùng tài nguyên đo được

**Nguồn số liệu.** Các maintainer đo ngày 2026-11-06 trên một máy: MacBook
Pro Apple M3 Max (arm64), Docker Desktop 28.4 với Linux VM 14 vCPU và
15.4 GiB, image `ghcr.io/guard-spec/guard-spec-gateway:0.1.0` (linux/arm64)
và `-control-plane:0.1.0`, model `guardspec-classifier@v3b` và
`multilingual-e5-small@614241f`. Bộ nhớ và CPU lấy từ `docker stats` (lấy mẫu
khoảng mỗi giây trong lúc chạy; CPU 100% = một core). Tải được tạo bằng
ApacheBench, 8 client đồng thời, gửi `POST /v1/chat/completions` gồm một
system message và một user prompt dài 350 ký tự, tới upstream giả (không đặt
`UPSTREAM_LLM_URL`), nên các con số là chi phí riêng của lớp bảo vệ; mỗi
request cũng ghi một dòng audit. Phần cứng khác, nhất là CPU x86-64, sẽ cho
kết quả khác: hãy tự đo trên máy của bạn (xem bên dưới) trước khi định cỡ cho
cả hệ thống.

### Không giới hạn (quick start, không đặt limit)

Gateway được dùng cả 14 vCPU; `INFERENCE_MAX_CONCURRENCY` mặc định bằng số CPU
(14) và ORT dùng 4 thread cho mỗi lần chạy.

| Lớp | RAM gateway khi rảnh | RAM gateway đỉnh | CPU gateway khi có tải (trung bình / đỉnh) | Request/s | Latency p50 / p95 / p99 |
|---|---|---|---|---|---|
| L1 | 10 MiB | 28 MiB | 2.9 / 4.0 cores | 1,784 | 3 / 6 / 13 ms |
| L1 + L2 | 483 MiB | 511 MiB | 9.3 / 10.1 cores | 387 | 19 / 31 / 43 ms |
| L1 + L2 + L3 | 909 MiB | 942 MiB | 12.9 / 15.6 cores | 137 | 53 / 103 / 152 ms |

### Với giới hạn của compose production

Mặc định của
[`deploy/compose/production`](../deploy/compose/production/README.vi.md):
gateway bị giới hạn 2 CPU và 2 GiB, `INFERENCE_MAX_CONCURRENCY=2`,
`INFERENCE_INTRA_OP_THREADS=1`; tải được gửi từ bên trong mạng compose thẳng
tới gateway.

| Lớp | RAM gateway khi rảnh | RAM gateway đỉnh | CPU gateway khi có tải | Request/s | Latency p50 / p95 / p99 |
|---|---|---|---|---|---|
| L1 | 11 MiB | 22 MiB | 1.5 cores | 2,168 | 2 / 9 / 23 ms |
| L1 + L2 | 481 MiB | 503 MiB | 1.9 cores | 118 | 68 / 74 / 79 ms |
| L1 + L2 + L3 | 904 MiB | 909 MiB | 1.9 cores | 55 | 138 / 166 / 288 ms |

Với 8 client và 2 lần chạy model cùng lúc, phần lớn latency đó là thời gian
xếp hàng: một lần quét mất khoảng 2 / throughput (17 ms ở chế độ nhẹ, 36 ms ở
chế độ đầy đủ trên CPU này).

### Các dịch vụ khác

| Dịch vụ | RAM | CPU |
|---|---|---|
| Control plane | khoảng 10 MiB, cả khi rảnh lẫn khi gateway có tải | dưới 1% |
| Postgres | 42 đến 66 MiB khi rảnh, tới 100 MiB với các mức tải ở trên | 0.3 core ở 137 lượt ghi audit/s, 0.6 ở 387, 1.8 ở 1,784 |
| Caddy (compose production) | tới 17 MiB | nhỏ |

## Khuyến nghị

Đây là điểm khởi đầu, lấy từ các bảng trên cộng thêm phần dư. Chỉ dòng "nhóm
nhỏ" khớp với một cấu hình đã đo; các dòng khác được ngoại suy từ đó.
Request/s chỉ tính riêng lớp bảo vệ; latency của LLM upstream cộng thêm vào,
và trong lúc chờ upstream, gateway không tốn CPU.

| Cách dùng | Lớp | Máy | Giới hạn gateway | Xử lý được khoảng |
|---|---|---|---|---|
| Cá nhân / laptop | `l1,l2` | 2 vCPU, còn trống 2 GB RAM | không đặt | vài chục request/s |
| Nhóm nhỏ, một VM | `l1,l2` | 2 vCPU, 4 GB | 2 CPU, 1 GiB | khoảng 100 request/s |
| Production cho startup, một VM | `l1,l2,l3` | 4 vCPU, 8 GB | 2 đến 3 CPU, 2 GiB | khoảng 50 đến 80 request/s |
| Lưu lượng lớn hơn | `l1,l2,l3` | nhiều replica gateway (Kubernetes, Helm chart) | mỗi replica 2 CPU, 2 GiB | thêm replica; throughput tăng theo số core |

- Bộ nhớ: cấp cho gateway ít nhất 1.5 lần mức đỉnh đo được (nhẹ 768 MiB,
  đầy đủ 1.5 GiB); trọng số model chỉ nạp một lần cho mỗi process, bất kể mức
  đồng thời.
- CPU: throughput tăng theo số core cho tới `INFERENCE_MAX_CONCURRENCY` x
  `INFERENCE_INTRA_OP_THREADS`; đặt tích của hai giá trị này bằng số CPU mà
  gateway được dùng. Đặt cao hơn chỉ làm tăng tranh chấp.
- `DETECTOR_CASCADE=true` bỏ qua L2 và L3 khi riêng L1 đã đủ để quyết định,
  giúp tiết kiệm CPU với lưu lượng rõ ràng; nó làm thay đổi điểm số, nên hãy
  kiểm tra trên lưu lượng của bạn trước.
- Rate limit (`RATE_LIMIT_RPM`) và timeout cho upstream giúp một đợt tăng đột
  biến không dồn hàng sau các lớp model.
- Kubernetes: mặc định cho gateway trong Helm chart (request 500m CPU / 1Gi,
  giới hạn bộ nhớ 2Gi) đủ cho mức đỉnh đo được của detector đầy đủ; đặt
  `INFERENCE_MAX_CONCURRENCY` và `INFERENCE_INTRA_OP_THREADS` theo giới hạn
  CPU như trên (`gateway.env`), và scale bằng `gateway.autoscaling` (HPA). Xem
  [`values.yaml`](../deploy/helm/guard-spec/values.yaml), các ví dụ cho từng
  cloud trong
  [`deploy/helm/guard-spec/examples/`](../deploy/helm/guard-spec/examples/)
  và [README, Kubernetes](../README.md#kubernetes).

## Ổ đĩa

- Model: khoảng 135 MB (nhẹ) hoặc 270 MB (đầy đủ) cho mỗi phiên bản được giữ,
  cộng với các phiên bản cũ bạn đã tải để rollback.
- Image (đã giải nén, arm64): gateway 285 MB, control plane 46 MB, Postgres
  415 MB, Caddy 88 MB.
- Postgres: bảng audit lớn dần theo từng request. Đo trên stack ở trên:
  20,020 dòng chiếm 7.4 MB kể cả index, tức khoảng **380 byte mỗi request**
  với mặc định `AUDIT_STORE_CONTENT=false` (chỉ lưu hash và độ dài).
  1 triệu request mỗi ngày, giữ theo mặc định 90 ngày
  (`AUDIT_RETENTION_DAYS`), là khoảng 34 GB. Nếu lưu cả nội dung thì cộng thêm
  kích thước của mọi prompt và response.
- Log: compose production giữ tối đa 50 MB cho mỗi container.

## Đo trên phần cứng của bạn

```bash
# 1. a key (see the README quick start), then a body like your traffic
cat > body.json <<'EOF'
{"model":"m","messages":[{"role":"user","content":"<a prompt of typical length>"}]}
EOF
# 2. load, while watching the containers
ab -n 5000 -c 8 -p body.json -T application/json -H "x-api-key: $KEY" \
  http://localhost:8080/v1/chat/completions
docker stats    # in another terminal
# 3. audit table size per row
docker compose exec postgres psql -U ps -d guardspec -c \
  "SELECT count(*), pg_size_pretty(pg_total_relation_size('requests')) FROM requests"
```

Chạy mà không đặt `UPSTREAM_LLM_URL` (trả lời giả) để thấy chi phí riêng của
lớp bảo vệ, và chạy một lần cho mỗi giá trị `DETECTOR_LAYERS` bạn đang cân
nhắc. Rất hoan nghênh bạn gửi kết quả đo trên phần cứng khác qua một issue.

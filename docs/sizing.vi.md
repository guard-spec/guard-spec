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

## Input dài

Một văn bản dài tốn CPU tỷ lệ với độ dài của nó: gateway cắt văn bản thành
các chunk 2,048 byte (văn bản không tin cậy được cắt trước thành các đoạn
24 KiB) và classifier chấm từng chunk theo cửa sổ 256 token. Hiện nay một
request mang tối đa 128 KiB văn bản không tin cậy (khoảng 30k token) và một
tin nhắn tối đa 16 chunk; các số dưới đây cho biết tài liệu lớn hơn sẽ tốn
bao nhiêu. Chất lượng phát hiện trên văn bản dài (false positive tăng theo độ
dài) nằm ở [benchmark, Tài liệu dài](benchmark.vi.md#tài-liệu-dài).

Đo bằng `make bench-long` (`cmd/benchlong`, bộ phát hiện `l1,l2`, lần lượt
từng tài liệu, K chunk của một tài liệu được chấm song song; tài liệu
Wikipedia 20k token tiếng Anh và tiếng Việt). `intra` là
`INFERENCE_INTRA_OP_THREADS`; "mặc định ORT" để ONNX Runtime dùng mọi core cho
mỗi lần chạy.

| Phần cứng | Nguồn | ms mỗi cửa sổ (intra 1) | Token/s, intra 1, K = 4 | Token/s, mặc định ORT, K = 4 | Token quét được trong 10 s (tốt nhất) | CPU-s mỗi 1k token | Tài liệu 20k token (tốt nhất) |
|---|---|---:|---:|---:|---:|---:|---:|
| 2 vCPU (AMD EPYC 9V74) | runner GitHub ubuntu-24.04, `taskset -c 0,1`, profile quick, 2026-11-09 | 60.3 | 2,879 (K = 2) | 4,571 (K = 2) | khoảng 50,000 | 0.41 (intra 1), 0.79 (mặc định) | 3.7 đến 4.2 s |
| 4 vCPU (AMD EPYC 7763) | runner GitHub ubuntu-24.04, profile full, 2026-11-09 | 101.0 | 3,106 | 2,784 | khoảng 31,000 | 0.69 (intra 1), 1.41 (mặc định) | 6.0 đến 6.9 s |
| Apple M3 Max, 14 core | M3 Max, máy local, chỉ mang tính tham khảo (2026-11-09, profile quick) | 61.8 | 9,209 | 17,551 | khoảng 175,000 | 0.42 (intra 1), 0.57 (mặc định) | 1.1 đến 1.2 s |
| 8 vCPU (x86) | ước tính | | khoảng 6,000 | | khoảng 60,000 | | khoảng 3 s |
| 16 vCPU (x86) | ước tính | | khoảng 12,000 | | khoảng 120,000 | | khoảng 1.5 s |
| GPU | chưa đo (task RF-b74de2b9) | | | | | | |

- Hai dòng runner là số đo, nhưng trên CPU khác nhau (GitHub tự chọn máy):
  job 2 vCPU được EPYC 9V74 đời mới hơn, job 4 vCPU được EPYC 7763 và còn chạy
  cả corpus full, nên dòng 2 vCPU nhanh hơn. vCPU cloud dùng chung dao động
  1,5 đến 2 lần giữa các lần chạy; hãy đọc như một khoảng.
- vCPU x86 trên cloud chậm hơn mỗi core M3 Max 3 đến 4 lần ở đây (khoảng 780
  token/s mỗi vCPU ở intra 1, K = 4 trên runner 4 vCPU, so với khoảng 2,300
  mỗi core M3 Max).
- Các dòng 8 và 16 vCPU là ước tính, không phải số đo: chúng nhân tốc độ mỗi
  vCPU của runner 4 vCPU tuyến tính theo số core, với giả định K và
  `INFERENCE_MAX_CONCURRENCY` tăng theo số core. Hãy thay bằng lần đo của bạn.
- Với ngân sách quét 10 s: khoảng 30k đến 50k token mỗi request trên 2 đến 4
  vCPU, 60k trên 8 và 120k trên 16 (ước tính); 200k token trong 10 s cần khoảng
  32 vCPU riêng hoặc GPU (chưa đo).
- CPU cho mỗi token gần như không đổi theo K hay intra: song song nhiều hơn
  rút ngắn thời gian của một tài liệu, không giảm chi phí của nó. Một server
  quét tài liệu cho nhiều người cùng lúc đạt cùng tổng throughput với intra 1
  và nhiều lần chạy đồng thời như với ít lần chạy rộng hơn.
- **Tài liệu 100k và 200k token, đã đo** (Apple M3 Max, 2026-11-11,
  `guardspec-classifier-v3b`, commit `2b805cc`; một tài liệu Wikipedia mỗi cỡ
  cho mỗi ngôn ngữ từ profile `long`, chấm riêng lẻ bằng
  `cmd/benchlong -docs`, `l1,l2`). Chi phí tuyến tính theo độ dài: một tài
  liệu 100k token mất 44.7 s (EN) / 39.8 s (VI) ở intra 1 với từng chunk một
  (2,200 đến 2,500 token/s, 0.45 / 0.39 CPU-s mỗi 1k token), 11.2 / 10.0 s với
  K = 4 (8,800 đến 10,100 token/s), và 6.6 / 5.7 s với số thread mặc định của
  ONNX Runtime và K = 4 (15,300 đến 17,900 token/s, 0.64 / 0.55 CPU-s mỗi 1k
  token); tài liệu 200k token mất gấp đôi (90.0 / 77.9 s, 22.7 / 19.6 s và
  13.1 / 11.1 s). Riêng classifier (`l2`, cửa sổ theo lô) quét 100k token
  trong 32.8 s ở intra 1 và 5.8 s với thread mặc định. Bốn tài liệu dài chấm
  cùng lúc (score pass của profile `long`, 128 tài liệu, 18.0M token sau
  sanitizer) đạt tổng 7,100 đến 7,900 token/s, 38 đến 42 phút cho cả profile.
  Trên runner cloud 4 vCPU, chậm hơn 3 đến 4 lần mỗi core, hãy tính khoảng 40
  đến 50 s cho mỗi 100k token trong trường hợp tốt nhất.
- **Tuyến dài của gateway tốn ít hơn các số theo chunk ở trên.** Khi đặt
  `MAX_SCAN_TOKENS`, một tài liệu vượt 128 KiB văn bản không tin cậy được
  tokenize một lần và chấm theo các cửa sổ 256 token của classifier, theo lô,
  mỗi cửa sổ được fuse với L1 (`ml.ScoreLong`), không theo chunk 2,048 byte.
  Đo đúng như khi chạy bằng `cmd/benchlong -long on` (Apple M3 Max,
  2026-11-11, `guardspec-classifier-v6` với cap và code corroboration, 4 tài
  liệu cùng lúc, số thread mặc định của ONNX Runtime): 128 tài liệu của
  profile `long` (18.0M token sau sanitizer) trong 19 phút, 15,600 token/s và
  0.51 CPU-s mỗi 1k token, so với 7,100 token/s và 1.49 CPU-s mỗi 1k token của
  phép đo theo chunk trên cùng các tài liệu (chạy classifier hai lần, theo cửa
  sổ cho `l2` và theo chunk cho `l1,l2`); 256 tài liệu 100k đến 200k token có
  một tấn công bên trong (31.9M token) đạt 17,900 token/s. Vậy một tài liệu
  100k token tốn khoảng 50 CPU-giây trên máy này, khoảng 26 s thời gian thực
  mỗi tài liệu khi bốn tài liệu được chấm cùng lúc trên 14 core (chưa đo
  riêng lẻ).
- Bảng đầy đủ của từng lần chạy (riêng L2, mọi K, thời gian từng tài liệu)
  nằm trong [`bench/results/long-m3max-local.md`](../bench/results/long-m3max-local.md),
  [`long-gh-ubuntu-24.04-4vcpu.md`](../bench/results/long-gh-ubuntu-24.04-4vcpu.md)
  và [`long-gh-ubuntu-24.04-2vcpu.md`](../bench/results/long-gh-ubuntu-24.04-2vcpu.md).
  Các lần chạy trên runner diễn ra trước bản sửa code/log của 0.4.2, nên bảng
  chặn nhầm trong đó là của detector 0.4.1; latency không bị ảnh hưởng.

### Đo input dài trên phần cứng của bạn

```bash
make bench-long                    # PROFILE=quick: about 1.6M tokens, about 7 minutes on an M3 Max
make bench-long PROFILE=full       # about 9.5M tokens
make bench-long PROFILE=long       # chỉ tài liệu lành tính 100k và 200k, 19M token, khoảng 40 phút mỗi model trên M3 Max
# your own documents, no Python needed: one .txt file per document
go run -tags onnx ./cmd/benchlong -docs ./my-docs -lang vi -host my-server
```

`make bench-long` cần [uv](https://docs.astral.sh/uv/) cho bộ dựng corpus và
tải các nguồn công khai đã ghim một lần vào `bench/.cache`. Cả hai cách đều
ghi `bench/results/long-<host>.json` và `.md`; cách `-docs` báo phân bố điểm,
false positive và latency trên văn bản của bạn (không có tấn công nên không có
tỷ lệ phát hiện). Ghim core bằng `taskset -c 0,1` và đặt
`INFERENCE_MAX_CONCURRENCY` tương ứng, như dòng 2 vCPU.

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

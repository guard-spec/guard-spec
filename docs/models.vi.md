<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Model: phiên bản, tải về, ghim và rollback

> English: [models.md](models.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Bộ phát hiện của gateway có ba lớp. L1 (luật) được build sẵn trong binary.
L2 (classifier của chúng tôi, `guardspec-classifier`) và L3 (embedder
`multilingual-e5-small`) là các model ONNX, không bao giờ được đóng sẵn vào
image hay commit vào git: chúng được tải về, kiểm tra rồi mount vào
`/models`.

[`models/manifest.yaml`](../models/manifest.yaml) liệt kê mọi phiên bản model
có thể tải về. Cùng file này được build vào gateway và công cụ `models`, nên
binary luôn biết các model nó khuyến nghị.

| Model | Phiên bản | Lớp | Khuyến nghị | Nguồn |
|---|---|---|---|---|
| `guardspec-classifier` | `v3b` | L2 | có | Hugging Face (chưa công bố), sau đó là GitHub Release `model-guardspec-classifier-v3b` |
| `guardspec-classifier` | `v4` | L2 | không: bản ứng viên, [so sánh ở shadow mode](#guardspec-classifier-v4-bản-ứng-viên) | GitHub Release `model-guardspec-classifier-v4` (khi chủ dự án công bố) |
| `guardspec-classifier` | `v5` | L2 | không: bản ứng viên cho code, log và tài liệu dài, [shadow mode trước](#guardspec-classifier-v5-bản-ứng-viên) | Hugging Face `guard-spec/guardspec-classifier` (nhánh `v5`), sau đó là GitHub Release `model-guardspec-classifier-v5` |
| `multilingual-e5-small` | `614241f` | L3 | có | Hugging Face `intfloat/multilingual-e5-small` |
| `protectai-deberta-v3-small-pi-v2` | `d7c8842` | baseline | tùy chọn, cần xin quyền truy cập | Hugging Face |
| `protectai-deberta-v3-base-pi-v2` | `90c9989` | baseline | tùy chọn | Hugging Face |

`models list --available` in ra danh sách hiện tại. Với các model không do
chúng tôi train, tên phiên bản là 7 ký tự đầu của revision Hugging Face đã
được ghim.

## Cấu trúc thư mục

Mỗi phiên bản được cài vào `<dir>/<name>/<version>/`; với compose, `<dir>` là
`./models/cache`:

```
models/cache/
  guardspec-classifier/v3b/     model_int8.onnx tokenizer.json config.json thresholds.json calibration.json
  multilingual-e5-small/614241f/  model.onnx tokenizer.json config.json
```

Nhiều phiên bản của cùng một model có thể nằm cạnh nhau; nhờ vậy rollback chỉ
cần một lần khởi động lại.

## Tải model

```bash
# Docker: models-init does this before the gateway starts, on every `up`
docker compose --profile models run --rm models-pull                           # recommended versions
docker compose --profile models run --rm models-pull guardspec-classifier@v3b  # one version

# Without Docker
go run ./cmd/models pull                              # recommended version of every non-optional model
go run ./cmd/models pull guardspec-classifier@v3b     # one version
go run ./cmd/models pull -models a,b@v1               # the older flag form still works
go run ./cmd/models list                              # what is installed
go run ./cmd/models list --available                  # what the manifest offers
go run ./cmd/models verify                            # re-check the SHA-256 of installed files
go run ./cmd/models init                              # như models-init: các model DETECTOR_LAYERS cần; tải lỗi chỉ cảnh báo, trừ khi -required
```

Những gì `pull` bảo đảm:

- **Được kiểm tra.** Mọi file đều được đối chiếu với kích thước và SHA-256 đã
  ghim trong manifest, bất kể tải từ nguồn nào. Không khớp thì bị từ chối.
- **Nguyên tử.** Một phiên bản được ráp trong một thư mục tạm ẩn nằm cạnh nó
  và chỉ được đổi tên vào đúng chỗ khi mọi file đã kiểm tra xong. Một lần pull
  lỗi hoặc bị ngắt giữa chừng giữ nguyên trạng thái trước đó.
- **Idempotent.** Khi một phiên bản đã có và kiểm tra đạt, không có gì được
  tải. File theo cấu trúc cũ, từ trước khi có phiên bản
  (`models/cache/multilingual-e5-small/model.onnx`), được dùng lại chứ không
  tải lần nữa.
- **Dự phòng.** Các nguồn được thử theo thứ tự: `-mirror` / `MODELS_MIRROR`
  nếu có đặt, Hugging Face ở commit đã ghim, rồi đến các `mirrors` trong
  manifest (asset của GitHub Release của chúng tôi). Khi một model chưa có
  trên Hugging Face, revision của nó là placeholder toàn số 0 và Hugging Face
  bị bỏ qua. `HF_TOKEN` chỉ bao giờ được gửi tới Hugging Face.

`MODELS_MIRROR` là một base URL phục vụ `<mirror>/<name>/<version>/<file>`,
dùng cho mirror nội bộ hoặc mạng bị giới hạn qua proxy. Bất kỳ server file tĩnh
nào phục vụ một bản sao của `models/cache` đều dùng được, ví dụ
`python3 -m http.server -d models/cache 8000` và
`MODELS_MIRROR=http://host.docker.internal:8000`.

## Chọn phiên bản trong gateway

Gateway xác định model cho từng lớp theo thứ tự sau:

1. `L2_MODEL_DIR` / `L3_MODEL_DIR`: dùng nguyên thư mục đó (các biến cũ; nếu
   được đặt thì chúng thắng);
2. `L2_MODEL` / `L3_MODEL` = `name@version`: `$MODEL_DIR/cache/<name>/<version>`.
   Chỉ ghi tên thì dùng phiên bản khuyến nghị của nó;
3. không đặt gì: model khuyến nghị trong manifest, nếu đã cài;
4. các thư mục từ trước khi có phiên bản: `$MODEL_DIR/local/guardspec-classifier-v3b`
   (rồi `-v2`, `-v1`, `-v0`) cho L2 và `$MODEL_DIR/cache/multilingual-e5-small`
   cho L3.

Một lựa chọn tường minh (1 hoặc 2) mà chưa được cài sẽ không bị thay bằng
model khác: lớp đó tắt và `/readyz` cho biết lý do. `MODEL_DIR` là `/models`
trong image và `./models` trong các trường hợp khác.

`GET /readyz` cho biết model nào đã được nạp:

```json
{"detector":{"layers":["l1","l2","l3"],"degraded":false,"onnx":true,"fusion":"logreg","l2_model":"guardspec-classifier-v3b"},"status":"ready","version":"0.1.0"}
```

## Ghim phiên bản

- **Image** được ghim bằng `GUARDSPEC_VERSION` (mặc định `0.1.0`). Mỗi image
  chứa manifest của release đó, nên các model nó khuyến nghị cũng được ghim
  theo.
- **Model** được ghim bằng `L2_MODEL=guardspec-classifier@v3b` (và
  `L3_MODEL`). Đặt chúng trong `.env` để giữ một phiên bản qua các lần nâng
  cấp image có khuyến nghị phiên bản mới hơn; models-init vẫn tải phiên bản
  khuyến nghị mới, nhưng gateway tiếp tục nạp phiên bản đã ghim.
- **File** được ghim bằng SHA-256 trong manifest, còn model upstream được ghim
  bằng commit Hugging Face của chúng.

## Rollback

1. Bảo đảm phiên bản cũ đã được cài:
   `docker compose --profile models run --rm models-pull guardspec-classifier@<old>`
   (`models list` cho biết những gì đang có).
2. Đặt `L2_MODEL=guardspec-classifier@<old>` trong `.env`.
3. Khởi động lại gateway: `docker compose up -d gateway`. Hoặc, không cần
   khởi động lại, gọi `POST /admin/models/reload` với
   `{"l2_model":"guardspec-classifier@<old>"}` (xem bên dưới), và vẫn giữ
   bước 2 cho lần khởi động sau.
4. Kiểm tra `/readyz` (`l2_model`, `models.l2_model`) và dòng log
   `L2 classifier loaded`.

Muốn hoàn tác thì xóa `L2_MODEL` và khởi động lại. Calibration đi kèm model
(`calibration.json` trong thư mục phiên bản), nên trọng số fusion luôn khớp
với classifier đang được nạp.

`calibration.json` chứa Platt scaling cho điểm của classifier (`platt`),
trọng số fusion theo bộ layer (`logreg`: `l1,l2` và `l1,l2,l3`) và, tùy
chọn, `l2_untrusted_max`: mức trần cho điểm đã hiệu chỉnh của classifier
trên tool result và document; vượt mức đó thì phải có rule (L1) hoặc lớp
similarity (L3) nâng thêm thì văn bản mới bị chặn. Chunk hoặc cửa sổ trên
đường dài bị hạ điểm vì mức trần mang rule `fusion.l2_capped`.
`go run -tags onnx ./cmd/calibrate fit -write` tính cả ba trên các tập
validation; file không có `l2_untrusted_max` (bản v3b đang phát hành) nghĩa
là không có mức trần. Shadow mode so sánh điểm fusion của các classifier
trước khi áp mức trần.

## So sánh bản ứng viên trước (shadow mode)

Trước khi chuyển, hãy chạy bản ứng viên song song với classifier đang dùng:

```bash
# .env
SHADOW_L2_MODEL=guardspec-classifier@<candidate>   # pulled first
SHADOW_SAMPLE=1                                    # share of requests compared
```

Nó chấm điểm cùng lưu lượng và ghi lại quyết định nó lẽ ra sẽ đưa ra vào
`shadow_results`; nó không bao giờ thay đổi quyết định và chạy ngoài đường
trả response. Trang **Models** của giao diện quản trị hiển thị tỷ lệ đồng
thuận, các request mà bản ứng viên sẽ chặn hoặc cho qua khác đi, và phân bố
điểm. Chi tiết nằm trong README, mục
[Shadow mode and model reload](../README.md#shadow-mode-and-model-reload).

### guardspec-classifier v4 (bản ứng viên)

`guardspec-classifier@v4` có trong manifest nhưng **không** phải phiên bản
khuyến nghị: v3b vẫn là mặc định cho đến khi v4 được so sánh ở shadow mode.
v4 dùng cùng kiến trúc và công thức train của v3b nhưng train trên nhiều dữ
liệu tiếng Việt hơn (các dòng teencode, không dấu và ngân hàng do chủ dự án
viết, cùng các hard negative mới); nó chặn ít tin nhắn tiếng Việt vô hại hơn.
Phần so sánh với v3b ở bên dưới ([v3b so với v4](#v3b-so-với-v4)) và trong
[train/MODEL_CARD.md](../train/MODEL_CARD.md) (mục "v4").

```bash
# 1. Install it next to v3b (files checked against the manifest's SHA-256).
#    It comes from the Hugging Face branch v4 at the pinned commit, with the
#    GitHub release model-guardspec-classifier-v4 as the mirror.
docker compose --profile models run --rm models-pull guardspec-classifier@v4
# 2. .env: keep v3b deciding, let v4 score the same traffic.
L2_MODEL=guardspec-classifier@v3b
SHADOW_L2_MODEL=guardspec-classifier@v4
SHADOW_SAMPLE=1
# 3. Restart the gateway (or POST /admin/models/reload), then watch the
#    Models page: agreement, requests v4 would block that v3b allows (and the
#    reverse), score distributions.
```

Nếu bạn có sẵn bản sao file ở máy (ví dụ trước khi release tồn tại), hãy đặt
`SHADOW_L2_MODEL_DIR=/path/to/guardspec-classifier-v4`; thư mục phải chứa
`model_int8.onnx`, `tokenizer.json`, `config.json`, `thresholds.json` và
`calibration.json` (calibration fusion của v4 nằm trong file đó). Khi kết quả
so sánh đạt yêu cầu, chuyển sang bằng `L2_MODEL=guardspec-classifier@v4` và
một lần reload; rollback thì làm ngược lại.

#### v3b so với v4

Điểm của gateway (kết hợp L1+L2+L3, chặn ở 0.85). Eval set chỉ được đo một
lần cho v4; owner hold-out là dữ liệu do chủ dự án viết mà không model nào
được train trên đó.

| | v3b | v4 |
|---|---|---|
| eval ROC AUC | 0.9865 | 0.9853 |
| eval TPR / FPR ở 0.85 | 0.939 / 1.39% (14 trên 1,005) | 0.932 / 1.19% (12) |
| eval EN FPR / VI FPR | 1.65% / 1.25% | 1.10% / 1.25% |
| eval FPR VI teencode / không dấu | 3.5% (5 trên 143) / 0.4% (1 trên 236) | 1.4% (2) / 1.7% (4) |
| owner hold-out FPR / TPR | 1.6% (3 trên 184) / 0.714 | 0.5% (1) / 0.688 |
| owner teencode/không dấu: FPR / TPR / ROC AUC | 4.2% (2 trên 48) / 0.417 / 0.763 | 2.1% (1) / 0.472 / 0.878 |
| False positive tiếng Việt vô hại (owner hold-out, `val_v4_holdout`, 4 câu được báo) | 11 trên 275 | 4 trên 275 |
| số câu bị chặn trong 4 câu được báo | 4 | 1 |

v4 chặn ít tin nhắn tiếng Việt vô hại hơn nhưng bắt được ít tấn công hơn một
chút (eval: ít hơn 7 trên 1,171; thấp hơn ở rò rỉ dữ liệu và tool poisoning
tiếng Việt, và ở leet tiếng Anh). Nó không vượt qua quy tắc quyết định đã đăng
ký trước, nên nó là bản ứng viên cho shadow mode chứ không phải mặc định.
[train/MODEL_CARD.md](../train/MODEL_CARD.md) (mục "v4") có đầy đủ các bảng.

### guardspec-classifier v5 (bản ứng viên)

`guardspec-classifier@v5` có trong manifest nhưng **không** phải phiên bản
khuyến nghị: v3b vẫn là mặc định cho đến khi v5 chạy ở shadow mode ít nhất 7
ngày và chủ dự án quyết định (dự kiến ở v0.5.0). v5 dùng cùng kiến trúc, công
thức train và nhãn của v3b, nhưng train theo từng cửa sổ (các cửa sổ 256 token
của gateway thay vì một dòng bị cắt ngắn) trên dữ liệu v4 cộng thêm code,
cấu hình, log, stack trace và văn xuôi dài vô hại làm hard negative, cùng các
tấn công được nhúng trong những văn bản đó (`train/DATA_CARD.md`, mục "v5
data"). Nó nhắm vào các false positive của v3b trên tool output như DDL,
Dockerfile, dòng log tiếng Việt, và các tấn công giấu trong code và log.

`calibration.json` của nó còn mang `l2_untrusted_max` (0.88): trên đường tool,
riêng classifier không thể chặn nội dung không tin cậy khi điểm đã hiệu chuẩn
vượt mức đó, L1 hoặc L3 phải góp phần còn lại. Giá trị này do `cmd/calibrate
fit` suy ra từ các split validation (không bao giờ từ `eval/`). Gateway không
biết trường này sẽ bỏ qua nó; đường trực tiếp (tin nhắn người dùng) không
thay đổi dù thế nào.

```bash
# 1. Install it next to v3b (files checked against the manifest's SHA-256;
#    Hugging Face at the pinned revision, else the GitHub release
#    model-guardspec-classifier-v5).
docker compose --profile models run --rm models-pull guardspec-classifier@v5
# 2. .env: keep v3b deciding, let v5 score the same traffic.
L2_MODEL=guardspec-classifier@v3b
SHADOW_L2_MODEL=guardspec-classifier@v5
SHADOW_SAMPLE=1
# 3. Restart the gateway (or POST /admin/models/reload), then watch the
#    Models page for at least 7 days: agreement, requests v5 would block that
#    v3b allows (and the reverse), score distributions, tool-result traffic.
```

Nếu có sẵn bản sao file ở máy, đặt
`SHADOW_L2_MODEL_DIR=/path/to/guardspec-classifier-v5` (thư mục phải chứa đủ
năm file ở trên). Chuyển sang bằng `L2_MODEL=guardspec-classifier@v5` và một
lần reload; rollback thì làm ngược lại.

#### v3b so với v5

Điểm của gateway (kết hợp L1+L2+L3, chặn ở 0.85), nửa hold-out của các eval
set và các owner hold-out, mỗi bộ chỉ chấm một lần. v3b dùng calibration đi
kèm; v5 dùng `calibration.json` của nó cùng cap.

| | v3b | v5 |
|---|---|---|
| `eval/data` (tin nhắn người dùng): TPR ở FPR ≤ 1% / TPR và FPR ở 0.85 | 0.942 / 0.9435 và 1.57% | 0.940 / 0.9435 và 1.17% |
| `eval/codelog` (tool output vô hại): FPR, corroboration tắt / bật | 20.99% / 7.41% | 0.62% / 0.62% |
| `eval/embedded` (tấn công trong code và log), corroboration tắt: TPR / FPR | 0.779 / 15.1% | 0.861 / 4.7% |
| `eval/embedded`, corroboration bật: TPR / FPR | 0.719 / 5.7% | 0.824 / 2.5% |
| `eval/embedded`: TPR ở FPR ≤ 1% | 0.374 | 0.748 |
| owner hold-out (408 tấn công / 272 vô hại): TPR / FPR ở 0.85 | 0.762 / 1.5% | 0.848 / 2.9% |
| owner hold-out: TPR ở FPR ≤ 1% | 0.503 | 0.797 |
| `val_v5_holdout` (host code và log, đường tool, corroboration tắt): FPR / TPR ở 0.85 / TPR ở FPR ≤ 1% | 0.9% / 0.665 / 0.665 | 0.0% / 0.623 / 0.988 |
| `val_v3_holdout` (tấn công và dòng vô hại sinh tự động): FPR / TPR ở 0.85 | 0.5% / 0.953 | 0.5% / 0.887 |
| số câu bị chặn trong 4 câu tiếng Việt được báo | 4 | 0 |

v5 loại bỏ phần lớn false positive trên tool output vô hại và bắt được nhiều
tấn công giấu trong code và log hơn; trên `eval/data` nó ngang v3b; trên
owner hold-out nó bắt được nhiều tấn công hơn với cái giá là chặn thêm 4
dòng vô hại (8 trên 272 so với 4). Hạn chế đã biết: với tài liệu 100k-200k
token, mục tiêu false positive chưa đạt (cần vòng dữ liệu thứ ba, văn xuôi vô
hại nhúng trong các host code và log); nó bắt được ít tấn công sinh tự động
của `val_v3_holdout` hơn ở ngưỡng chặn (0.887 so với 0.953); và trên đường
tool, cap giữ các tấn công nhúng mà chỉ classifier nhận ra ở dưới ngưỡng chặn
(`val_v5_holdout`: 0.623 so với 0.665 ở 0.85, dù xếp hạng tốt hơn nhiều). Quy
tắc chọn, mọi bảng số và dữ liệu nằm trong
[train/MODEL_CARD.md](../train/MODEL_CARD.md) (mục "v5").

## Nạp lại không cần khởi động lại

`kill -HUP` gateway, hoặc `POST /admin/models/reload` với
`GATEWAY_ADMIN_TOKEN`, sẽ nạp lại classifier (hoặc một phiên bản khác), kiểm
tra mọi file với SHA-256 trong manifest, rồi thay vào mà không làm rơi request
nào. Nếu lỗi, model đang chạy được giữ nguyên. Các phiên bản không có trong
manifest dựng sẵn (model của riêng bạn) cần một file manifest liệt kê chúng,
chỉ ra bằng `MODELS_MANIFEST`, cùng định dạng với `models/manifest.yaml`.

## Cài đặt air-gapped

Có hai cách:

- **Image `gateway-full`**, chứa sẵn các model khuyến nghị của release đó
  (build từ `build/gateway-full.Dockerfile`). Chuyển nó bằng
  `docker save` / `docker load`. Nó không cần models-init tải về; đặt
  `MODEL_DIR` theo tài liệu của image.
- **Một bản sao của `models/cache`.** Trên máy có mạng, chạy `models pull`,
  sao chép thư mục, rồi trên máy đích chạy `models verify` trước khi khởi
  động. Khi đó models-init thấy file đã có và kiểm tra đạt nên không làm gì.
  Hoặc bạn có thể phục vụ bản sao từ một server file nội bộ và đặt
  `MODELS_MIRROR`.

Không có mạng và không có model, models-init sẽ cảnh báo và gateway chỉ chạy
L1 (`/readyz` liệt kê các lớp thiếu), trừ khi `DETECTOR_REQUIRE_ML=true`, khi
đó cả stack dừng lại.

## False positive: sửa ngay bằng exemplar

Một phiên bản model mới cần một lần train, một lần eval và một release. Cách
sửa false positive (chặn nhầm) ngay hôm nay là trang **Exemplars** của giao
diện quản trị (`/ui/`, hoặc `POST /v1/organizations/:orgId/exemplars`):

- thêm văn bản bị chặn nhầm thành một exemplar **allow**: nó hạ điểm L3 của
  các request tương tự trong organization đó; exemplar **block** làm điều
  ngược lại và đặt một mức sàn cho điểm tổng hợp;
- xem `scores` của request trong request log trước: exemplar allow chỉ tác
  động lên L3, nên khi chỉ riêng L2 đẩy điểm lên thì nó chỉ hạ được điểm tổng
  hợp một phần. Hãy báo những văn bản như vậy (không kèm dữ liệu khách hàng)
  để phiên bản model sau học được từ chúng;
- exemplar cần model L3 và có hiệu lực trong khoảng 5 giây, không cần khởi
  động lại.

## Phát hành phiên bản model mới

Dành cho maintainer. Ví dụ dưới đây phát hành `guardspec-classifier` `v4`.

1. **Train** bằng `train/` (xem [train/MODEL_CARD.md](../train/MODEL_CARD.md)).
   Chọn số epoch, threshold và calibration chỉ dựa trên các validation split.
   `eval/` không bao giờ được dùng để tinh chỉnh.
2. **Calibrate**: `go run -tags onnx ./cmd/calibrate fit -write` ghi
   `calibration.json` cạnh model; đồng thời thêm các giá trị vào
   `BuiltinCalibrations` trong `internal/inference/ml/calibration.go`.
3. **Đánh giá một lần** trên `eval/` với model cuối cùng và ghi số liệu vào
   model card. Không quay lại bước 1 vì những số này; model không đạt eval set
   thì không được phát hành (như với v3).
4. **Băm** các file: `shasum -a 256 model_int8.onnx tokenizer.json config.json thresholds.json calibration.json`
   và ghi lại kích thước.
5. **Upload** đúng các file đó lên Hugging Face (repo ghi trong manifest) và
   ghi lại commit sha; sau đó đính kèm chúng làm asset của một GitHub Release
   có tag `model-guardspec-classifier-v4` (một release model, không phải
   release phần mềm `v*`).
6. **Cập nhật manifest**: thêm một mục với `version: v4`, `revision` Hugging
   Face, mirror
   `https://github.com/guard-spec/guard-spec/releases/download/model-guardspec-classifier-v4/{file}`
   và `size`, `sha256` của từng file. Chuyển `recommended: true` từ mục cũ
   sang mục mới, và giữ mục cũ để rollback vẫn hoạt động.
7. **Kiểm tra**: `go test ./internal/onnx ./internal/inference/ml`, sau đó
   pull vào một thư mục trống (`go run ./cmd/models pull -dir /tmp/m guardspec-classifier@v4`)
   để chứng minh cả hai nguồn đều phục vụ đúng các file đã ghim.
8. **CHANGELOG**: thêm mục "Model" dưới Unreleased với phiên bản, những thay
   đổi về dữ liệu, và số liệu eval so với phiên bản trước.
9. **Ký** GitHub Release khi thay đổi manifest đã vào `main`: chạy workflow
   *Sign model release* (`gh workflow run sign-model-release.yml -f version=v4`).
   Workflow kiểm tra mọi file với các giá trị ghim mới rồi đính kèm
   `SHA256SUMS` cùng bundle cosign của nó
   ([cách xác minh](security/verifying-releases.md#5-models), tiếng Anh).

Release phần mềm kế tiếp sau đó sẽ mang manifest khuyến nghị v4.

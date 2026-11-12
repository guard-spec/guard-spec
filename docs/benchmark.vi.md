# Benchmark: Guard Spec và các bộ phát hiện prompt injection khác

> English: [benchmark.md](benchmark.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Trang này so sánh bộ phát hiện của Guard Spec với các bộ phát hiện prompt
injection mã nguồn mở khác, trên eval set của chính Guard Spec và trên các
dataset công khai. Mọi thứ ở đây đều ra từ một lệnh duy nhất, với mọi dataset
và model được ghim phiên bản, nên ai cũng có thể chạy lại và kiểm tra các con số.

Đây chỉ là một phép đo, không hơn. Không có threshold, trọng số hay rule nào
của Guard Spec được tinh chỉnh trên các dataset này hay trên `eval/` để phục vụ
trang này, và các detector khác chạy với cấu hình mặc định mà chúng công bố.

- [Tóm tắt](#tóm-tắt)
- [Tái lập kết quả](#tái-lập-kết-quả)
- [Đo những gì](#đo-những-gì)
- [Dataset](#dataset-và-giấy-phép)
- [Detector](#các-detector)
- [Kết quả](#kết-quả)
- [Thảo luận](#thảo-luận)
- [Tài liệu dài](#tài-liệu-dài)

## Tóm tắt

Chạy ngày 2026-11-07 (19:30 UTC ngày 2026-11-06) ở commit `2e182a0` (v0.2.1)
bằng harness của benchmark này, trên laptop Apple M3 Max (macOS 15.4.1); các
bảng đầy đủ nằm ở mục [Kết quả](#kết-quả). Quyết định mặc định, mọi ngôn ngữ:

| Dataset | Guard Spec L1+L2+L3: AUC / TPR / FPR | ProtectAI v2: AUC / TPR / FPR | LLM Guard default: TPR / FPR |
|---|---|---|---|
| `eval/` (EN + VI, 2,176 rows) | 0.987 / 95.0% / 1.4% | 0.784 / 88.6% / 50.6% | 83.0% / 45.6% |
| `deepset` test (116, half German/Spanish) | 0.963 / 33.3% / 0.0% | 0.901 / 36.7% / 0.0% | 31.7% / 0.0% |
| `jailbreak-classification` test (262) | 0.994 / 92.1% / 0.0% | 0.979 / 84.2% / 1.6% | 84.2% / 1.6% |
| `Gandalf` test (112, attacks only) | - / 100% / - | - / 100% / - | 100% / - |
| `SPML` sample (2,000) | 0.974 / 36.4% / 0.0% | **0.997 / 99.2% / 8.4%** | 99.1% / 6.6% |

- Trên bộ của chính chúng tôi, Guard Spec dẫn xa, điều này là dự đoán được và
  **không phải phép thử công bằng cho ProtectAI**: một nửa `eval/` là tiếng
  Việt (ProtectAI chỉ hỗ trợ tiếng Anh) và các dòng lành tính của nó là hard
  negative, được viết sao cho trông giống tấn công. Trên nửa tiếng Anh,
  ProtectAI đạt AUC 0.897 và gắn cờ 23% số dòng lành tính.
- Trên **SPML**, bộ công khai duy nhất mà không detector nào ở đây được train
  trên đó, **ProtectAI rõ ràng tốt hơn**: AUC 0.997 so với 0.974 và, ở cùng
  FPR 1%, bắt được 97.6% tấn công so với 84.5% (89.2% với L1+L2). Ở threshold
  mặc định, Guard Spec chỉ chặn 36% tấn công của SPML, không có false positive
  (chặn nhầm) nào; ProtectAI chặn 99% với 8% false positive.
- Trên `deepset` và `jailbreak-classification`, Guard Spec xếp hạng tốt hơn
  (AUC), nhưng classifier của Guard Spec được train trên split `train` của hai
  bộ này, nên hai dòng đó nghiêng về phía nó. Trên `deepset`, cả hai detector
  chỉ chặn khoảng một phần ba số tấn công ở cấu hình mặc định.
- Guard Spec nhỏ hơn (237 MB int8 so với 739 MB fp32) và nhanh hơn trên mỗi
  dòng (p50 5–8 ms so với 32–67 ms với input ngắn, một thread). Phép so sánh
  này không cùng điều kiện: model của chúng tôi là int8, còn file ONNX mà
  ProtectAI công bố là fp32.
- Meta Prompt Guard 2 bị giới hạn truy cập (gated) nên không có trong các bảng
  này; ai có quyền truy cập có thể thêm nó bằng một biến
  ([xem bên dưới](#đưa-meta-prompt-guard-2-vào)).

## Tái lập kết quả

```bash
make benchmark
```

Target đó tải ONNX Runtime và libtokenizers (`make onnx-deps`, ghim bằng
SHA-256), chạy `bench/run.py` với các package Python được khoá trong
`bench/uv.lock` (cần [uv](https://docs.astral.sh/uv/)), rồi ghi ra:

- `bench/results/results.json`: mọi metric, thông tin máy và các phiên bản;
- `bench/results/results.md`: các bảng;
- phần được sinh tự động của trang này (giữa hai marker `bench:begin` và
  `bench:end`).

Nó làm những việc sau:

1. Tải các dataset công khai ở đúng commit Hugging Face đã ghim và chuyển
   chúng sang schema dòng của `eval/`.
2. Kéo các model bằng `go run ./cmd/models pull`, lệnh này kiểm tra từng file
   với giá trị SHA-256 trong `models/manifest.yaml`:
   `guardspec-classifier@v3b`, `multilingual-e5-small@614241f` và
   `protectai-deberta-v3-base-pi-v2@90c9989`.
3. Chạy Guard Spec qua `cmd/eval -scores` (build với `-tags onnx`), tức đúng
   đường xử lý input của gateway: sanitizer, các lớp detector, fusion và rule
   chặn của `/v1/scan`.
4. Chạy model ProtectAI trong ONNX Runtime từ Python.
5. Tính các metric bên dưới cho từng detector, dataset và ngôn ngữ.

Tuỳ chọn:

| Biến | Mặc định | Tác dụng |
|---|---|---|
| `BENCH_CACHE` | `bench/.cache` | Downloads, converted datasets, per-row scores. About 1.2 GB (ProtectAI's ONNX file is 739 MB). The run stops when less than 6 GB is free there. |
| `MODEL_DIR` | `$BENCH_CACHE/models` | Use already pulled Guard Spec models (`<dir>/cache/<name>/<version>`) instead of pulling them. |
| `ONNX_DIR` | `.onnx` | Where `make onnx-deps` puts the native libraries. |
| `PROMPTGUARD=1` | off | Also run Meta Prompt Guard 2, see below. |

GitHub Actions: workflow **Benchmark** (`.github/workflows/benchmark.yml`)
chạy `make benchmark` trên `ubuntu-24.04` khi được khởi động bằng tay (Actions >
Benchmark > Run workflow); nó không bao giờ tự chạy. Workflow ghi các bảng vào
job summary và tải `bench/results/` cùng trang này lên dưới dạng artifact
`benchmark-results`.

### Đưa Meta Prompt Guard 2 vào

`meta-llama/Llama-Prompt-Guard-2-86M` và `-22M` bị giới hạn truy cập (gated)
trên Hugging Face theo Llama 4 Community License: không thể tải chúng nếu
không có tài khoản đã chấp nhận điều khoản, nên chúng không có trong các bảng
đã công bố. Nếu bạn có quyền truy cập:

1. Chấp nhận giấy phép trên trang của cả hai model.
2. Export một token chỉ đọc của tài khoản đó thành `HF_TOKEN` trong shell
   (`huggingface_hub` đọc biến này; `bench/run.py` không bao giờ đọc, in ra
   hay lưu nó).
3. Chạy `make benchmark PROMPTGUARD=1`. Lệnh này cài extra `promptguard`
   (PyTorch và Transformers, CPU) và thêm hai dòng detector, ở các revision đã
   ghim `a8ded8e` (86M) và `11614a1` (22M), dùng quyết định argmax của model
   (xác suất malicious ≥ 0.5), 512 token đầu, một thread.

Trong workflow, thêm token làm repository secret `HF_READ_TOKEN` và đánh dấu
"promptguard" khi khởi động lần chạy.

## Đo những gì

Với mỗi tổ hợp detector × dataset × ngôn ngữ:

- **ROC AUC** của score do detector trả về, kèm khoảng bootstrap 95% (1,000
  lần lấy mẫu lại, seed cố định). Chỉ số này không phụ thuộc threshold nào.
- **TPR và FPR ở quyết định mặc định**: tỉ lệ dòng tấn công và dòng lành tính
  mà detector gắn cờ với cấu hình mặc định nó công bố. Với Guard Spec, đó là
  rule `/v1/scan` của gateway (score của detector ≥ 0.85, hoặc anomaly của
  sanitizer ≥ 0.6, hoặc input bị sanitizer từ chối), tức quyết định mà một bản
  triển khai thực sự đưa ra.
- **TPR ở FPR ≤ 1%**: tỉ lệ tấn công bắt được ở threshold thấp nhất mà vẫn
  chỉ gắn cờ tối đa 1% số dòng lành tính của nhóm đó. Threshold được chọn sau
  khi đã có kết quả, trên chính các dòng đó, áp dụng như nhau cho mọi detector,
  nên đây là giới hạn trên của những gì một threshold được tinh chỉnh có thể
  đạt; nó so sánh thứ hạng score, không so sánh cấu hình mặc định. Khi có ít
  hơn 100 dòng lành tính, nó có nghĩa là "không có false positive nào".
- **Latency p50 / p95** trên mỗi dòng, tính bằng mili giây: chạy từng dòng một
  trên một máy, ONNX Runtime (hoặc PyTorch) đặt một intra-op thread. Với Guard
  Spec, đó là sanitizer cộng detector đúng như gateway chạy; khi bật cả L2 và
  L3, gateway chấm điểm hai model song song, nên cấu hình đó có thể dùng hai
  core cho một dòng. Với các detector Python, đó là bước tokenization cộng lời
  gọi model. Với các detector Python, năm dòng warm-up không được tính giờ;
  `cmd/eval` tính giờ mọi dòng, không tính thời gian nạp model.
- **Kích thước model**: dung lượng trên đĩa của các trọng số model mà detector
  nạp.

Dataset không có dòng lành tính (Gandalf) chỉ có TPR.

## Dataset và giấy phép

Mọi dataset đều được kiểm tra trên trang (card) Hugging Face ở commit đã ghim.
Benchmark tải chúng khi chạy; repository này không lưu dòng nào của chúng ngoài
những gì `eval/` vốn đã có (xem [eval/LICENSES.md](../eval/LICENSES.md)).

| Dataset | Giấy phép | Có dùng | Lý do |
|---|---|---|---|
| `eval/` (Guard Spec) | Apache-2.0 (project rows), Apache-2.0 / MIT (sourced rows) | yes | Our published EN/VI set. |
| [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | yes, `test` | Standard small benchmark; mixed English and German/Spanish. |
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | yes, balanced `test` | Jailbreak prompts versus benign prompts. |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | yes, `test` | Real attacks from the Gandalf game (attacks only). |
| [`reshabhs/SPML_Chatbot_Prompt_Injection`](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | MIT | yes, 1,000 rows per label, seeded sample | Chatbot-specific injections; no detector here trained on it. |
| `xTRam1/safe-guard-prompt-injection` | none on the card (revision `a3a877d608f3`) | no | No license. |
| `Lakera/mosscap_prompt_injection` | MIT | no | Unlabelled: every prompt sent to the game, attack or not. |
| `jayavibhav/prompt-injection` | none on the card | no | No license. |

Số dòng và ngôn ngữ của mỗi lần chạy nằm trong các bảng sinh tự động bên dưới.

**Tiếng Việt.** Chúng tôi không tìm được dataset prompt injection tiếng Việt
nào vừa công khai vừa có giấy phép. Các dòng tiếng Việt duy nhất ở đây là của
`eval/`, vốn là dữ liệu tổng hợp và được gán nhãn bởi AI agent (xem
[eval/README.md](../eval/README.md)).

**Cột ngôn ngữ.** `eval/` gắn ngôn ngữ cho từng dòng (`en`, `vi`). Với các bộ
công khai, dòng nào có dấu hiệu tiếng Đức, tiếng Tây Ban Nha hoặc chữ Cyrillic
(theo rule của `eval/build/build.py`) được xếp vào `other`, còn lại là `en`.
Chỉ `deepset` có tỉ lệ `other` đáng kể.

**Trùng lặp với dữ liệu train.** Hãy lưu ý điều này khi đọc các dòng công khai:

- Classifier của Guard Spec (L2, v3b) được train trên split `train` của
  `deepset/prompt-injections`, `Lakera/gandalf_ignore_instructions` và
  `jackhhao/jailbreak-classification` ([train/DATA_LICENSES.md](../train/DATA_LICENSES.md)).
  Benchmark chỉ dùng split `test` của chúng, nhưng các split này có cùng phân
  phối, nên có lợi cho Guard Spec trên ba bộ này.
- ProtectAI v2 liệt kê `jackhhao/jailbreak-classification` trong các bộ dữ
  liệu train của nó (không nói rõ split nào), nên điều tương tự cũng đúng với
  nó ở bộ đó.
- Các dòng `test` tiếng Anh của `deepset` và `Gandalf` cũng nằm trong `eval/`
  (60 trên 116 và 111 trên 112 dòng).
- Các rule L1 của Guard Spec được tinh chỉnh bằng cách xem các lỗi trên nửa
  "dev" của `eval/` ([eval/README.md](../eval/README.md)); số liệu L1 trên
  `eval/` vì vậy là lạc quan. L2, L3 và fusion chưa bao giờ được fit trên
  `eval/`.
- Không có gì trong benchmark này được dùng để thay đổi Guard Spec.

## Các detector

| Detector | Có đưa vào | Ghi chú |
|---|---|---|
| Guard Spec L1 | yes | Rules only, the default build without models (`cmd/eval -detector fusion`). |
| Guard Spec L1+L2 | yes | Rules + classifier v3b (`-layers l1,l2`). |
| Guard Spec L1+L2+L3 | yes | Rules + classifier + embeddings, the default with models (`-layers l1,l2,l3`). |
| ProtectAI `deberta-v3-base-prompt-injection-v2` | yes | Apache-2.0. The published fp32 ONNX export, first 512 tokens, flags when P(INJECTION) ≥ 0.5 (argmax of the model card's pipeline). |
| LLM Guard `PromptInjection` | as a threshold of the ProtectAI row | llm-guard 0.3.16 (MIT, archived) wraps the same model: its default pins revision `89b085c`, whose weights are byte-identical to `90c9989` (same SHA-256), reads the first 512 tokens (`match_type=FULL`) and flags when `round(score, 2) > 0.92`. Installing it would only rerun the same model, so its row reuses the ProtectAI scores with that rule: same AUC, different TPR/FPR. Its default runs the model in PyTorch rather than ONNX, so latency is not reported separately. |
| Meta Llama Prompt Guard 2 (86M, 22M) | no (gated) | Llama 4 Community License, gated on Hugging Face; see [Including Meta Prompt Guard 2](#đưa-meta-prompt-guard-2-vào). |

## Kết quả

<!-- bench:begin -->
Chạy lúc 2026-11-06 19:30 UTC, commit `2e182a03bc62`, máy local: Apple M3 Max, 14 logical CPU, 36 GB RAM, macOS 15.4.1 (arm64). go1.26.10, ONNX Runtime 1.31.1 (Go) / 1.31.1 (Python), Python 3.12.0.

### Các dataset

| Dataset | Revision | License | Split | Rows (attack / benign) | Languages |
|---|---|---|---|---|---|
| Guard Spec eval set (eval/) | this commit | Apache-2.0 (project rows); Apache-2.0 / MIT for the deepset / Gandalf rows it includes | eval/data/en.jsonl, vi.jsonl | 2176 (1171 / 1005) | en 926, vi 1250 |
| [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | `4f61ecb038e9` | Apache-2.0 | test | 116 (60 / 56) | en 60, other 56 |
| [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | `2f2ceeb39658` | Apache-2.0 | balanced test | 262 (139 / 123) | en 259, other 3 |
| [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | `04737b65e90a` | MIT | test | 112 (112 / 0) | en 111, other 1 |
| [`reshabhs/SPML_Chatbot_Prompt_Injection`](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | `02ce8084e979` | MIT | seeded sample, 1000 per label | 2000 (1000 / 1000) | en 1995, other 5 |

### Các detector đã chạy

| Detector | Model files | Size on disk | Runtime | Default decision |
|---|---|---:|---|---|
| Guard Spec L1 | rules only (no model) | 0 (rules) | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| Guard Spec L1+L2 | guardspec-classifier/v3b | 119 MB | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| Guard Spec L1+L2+L3 | guardspec-classifier/v3b; multilingual-e5-small/614241f | 237 MB | Go, ONNX Runtime (int8 models), 1 intra-op thread per session | gateway /v1/scan rule: score >= 0.85, sanitizer anomaly >= 0.6, or input rejected |
| ProtectAI v2 | protectai/deberta-v3-base-prompt-injection-v2@90c9989 (onnx/model.onnx, fp32) | 739 MB | Python, ONNX Runtime 1.31.1 (fp32), 1 intra-op thread | INJECTION probability >= 0.5 (argmax, model card pipeline) |
| LLM Guard PromptInjection (default) | protectai/deberta-v3-base-prompt-injection-v2@90c9989 (onnx/model.onnx, fp32) | 739 MB | Python, ONNX Runtime 1.31.1 (fp32), 1 intra-op thread | llm-guard 0.3.16 defaults: same model, match_type FULL (first 512 tokens), flag when round(score, 2) > 0.92 |

Không chạy: Meta Llama Prompt Guard 2 (86M, 22M): bị giới hạn truy cập trên Hugging Face (Llama 4 Community License); chạy với --promptguard và HF_TOKEN của riêng bạn sau khi chấp nhận điều khoản.

### Eval set của Guard Spec (eval/)

Được công bố cùng repository này. L2, L3 và fusion chưa bao giờ được fit trên bộ này; các rule L1 được tinh chỉnh trên nửa dev của nó, nên số liệu L1 ở đây là lạc quan (eval/README.md).

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 1171 / 1005 | 0.952 [0.943, 0.962] | 89.2% | 0.1% | 91.0% | 0.11 | 0.22 |
| Guard Spec L1 | en | 562 / 364 | 0.929 [0.911, 0.945] | 84.2% | 0.3% | 86.7% | 0.11 | 0.21 |
| Guard Spec L1 | vi | 609 / 641 | 0.975 [0.964, 0.984] | 93.9% | 0.0% | 94.9% | 0.11 | 0.23 |
| Guard Spec L1+L2 | all | 1171 / 1005 | 0.987 [0.982, 0.992] | 94.9% | 1.4% | 93.3% | 6.02 | 22.01 |
| Guard Spec L1+L2 | en | 562 / 364 | 0.982 [0.973, 0.989] | 94.0% | 1.6% | 90.4% | 5.49 | 19.73 |
| Guard Spec L1+L2 | vi | 609 / 641 | 0.991 [0.984, 0.996] | 95.7% | 1.2% | 94.9% | 6.51 | 23.95 |
| Guard Spec L1+L2+L3 | all | 1171 / 1005 | 0.987 [0.981, 0.991] | 95.0% | 1.4% | 93.4% | 6.47 | 21.90 |
| Guard Spec L1+L2+L3 | en | 562 / 364 | 0.980 [0.970, 0.988] | 94.1% | 1.6% | 90.9% | 6.10 | 19.62 |
| Guard Spec L1+L2+L3 | vi | 609 / 641 | 0.992 [0.985, 0.997] | 95.7% | 1.2% | 94.7% | 6.91 | 23.46 |
| ProtectAI v2 | all | 1171 / 1005 | 0.784 [0.764, 0.802] | 88.6% | 50.6% | 26.2% | 66.89 | 237.54 |
| ProtectAI v2 | en | 562 / 364 | 0.897 [0.877, 0.917] | 86.8% | 23.4% | 35.1% | 46.41 | 169.34 |
| ProtectAI v2 | vi | 609 / 641 | 0.661 [0.632, 0.690] | 90.1% | 66.1% | 5.9% | 76.69 | 262.98 |
| LLM Guard PromptInjection (default) | all | 1171 / 1005 | 0.784 [0.764, 0.802] | 83.0% | 45.6% | 26.2% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | en | 562 / 364 | 0.897 [0.877, 0.917] | 84.0% | 20.3% | 35.1% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | vi | 609 / 641 | 0.661 [0.632, 0.690] | 82.1% | 59.9% | 5.9% | same model as ProtectAI v2 |  |

### deepset/prompt-injections

Khoảng một nửa số dòng là tiếng Đức hoặc tiếng Tây Ban Nha (lang 'other'). Các dòng test tiếng Anh cũng có trong eval/; classifier của Guard Spec được train trên split train.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 60 / 56 | 0.757 [0.674, 0.835] | 13.3% | 0.0% | 28.3% | 0.10 | 0.26 |
| Guard Spec L1 | en | 31 / 29 | 0.877 [0.777, 0.953] | 22.6% | 0.0% | 45.2% | 0.10 | 0.21 |
| Guard Spec L1 | other | 29 / 27 | 0.710 [0.621, 0.799] | 3.4% | 0.0% | 24.1% | 0.10 | 0.38 |
| Guard Spec L1+L2 | all | 60 / 56 | 0.955 [0.913, 0.987] | 35.0% | 0.0% | 88.3% | 4.71 | 18.23 |
| Guard Spec L1+L2 | en | 31 / 29 | 0.958 [0.883, 1.000] | 45.2% | 0.0% | 90.3% | 4.33 | 14.94 |
| Guard Spec L1+L2 | other | 29 / 27 | 0.971 [0.930, 0.997] | 24.1% | 0.0% | 86.2% | 4.74 | 27.29 |
| Guard Spec L1+L2+L3 | all | 60 / 56 | 0.963 [0.921, 0.991] | 33.3% | 0.0% | 83.3% | 5.42 | 18.53 |
| Guard Spec L1+L2+L3 | en | 31 / 29 | 0.973 [0.914, 1.000] | 45.2% | 0.0% | 93.5% | 5.14 | 15.54 |
| Guard Spec L1+L2+L3 | other | 29 / 27 | 0.941 [0.874, 0.989] | 20.7% | 0.0% | 82.8% | 5.73 | 27.70 |
| ProtectAI v2 | all | 60 / 56 | 0.901 [0.839, 0.951] | 36.7% | 0.0% | 53.3% | 45.10 | 196.72 |
| ProtectAI v2 | en | 31 / 29 | 0.889 [0.796, 0.959] | 25.8% | 0.0% | 71.0% | 39.97 | 123.84 |
| ProtectAI v2 | other | 29 / 27 | 0.936 [0.866, 0.985] | 48.3% | 0.0% | 58.6% | 53.32 | 267.84 |
| LLM Guard PromptInjection (default) | all | 60 / 56 | 0.901 [0.839, 0.951] | 31.7% | 0.0% | 53.3% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | en | 31 / 29 | 0.889 [0.796, 0.959] | 22.6% | 0.0% | 71.0% | same model as ProtectAI v2 |  |
| LLM Guard PromptInjection (default) | other | 29 / 27 | 0.936 [0.866, 0.985] | 41.4% | 0.0% | 58.6% | same model as ProtectAI v2 |  |

### jackhhao/jailbreak-classification

Prompt jailbreak (nhập vai) so với prompt lành tính. Classifier của Guard Spec được train trên split train đã cân bằng; ProtectAI v2 liệt kê dataset này trong các nguồn dữ liệu train của nó.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 139 / 123 | 0.961 [0.942, 0.977] | 66.9% | 0.0% | 84.9% | 0.43 | 2.99 |
| Guard Spec L1+L2 | all | 139 / 123 | 0.993 [0.984, 0.999] | 92.1% | 0.0% | 93.5% | 42.14 | 507.41 |
| Guard Spec L1+L2+L3 | all | 139 / 123 | 0.994 [0.986, 0.999] | 92.1% | 0.0% | 93.5% | 41.87 | 511.62 |
| ProtectAI v2 | all | 139 / 123 | 0.979 [0.956, 0.995] | 84.2% | 1.6% | 69.8% | 327.75 | 1161.58 |
| LLM Guard PromptInjection (default) | all | 139 / 123 | 0.979 [0.956, 0.995] | 84.2% | 1.6% | 69.8% | same model as ProtectAI v2 |  |

### Lakera/gandalf_ignore_instructions

Chỉ có tấn công (không có dòng lành tính): chỉ TPR là xác định được. Các dòng test tiếng Anh cũng có trong eval/; classifier của Guard Spec được train trên split train.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 112 / 0 | - | 77.7% | - | - | 0.10 | 0.19 |
| Guard Spec L1+L2 | all | 112 / 0 | - | 100.0% | - | - | 3.90 | 7.13 |
| Guard Spec L1+L2+L3 | all | 112 / 0 | - | 100.0% | - | - | 4.87 | 8.22 |
| ProtectAI v2 | all | 112 / 0 | - | 100.0% | - | - | 32.18 | 62.98 |
| LLM Guard PromptInjection (default) | all | 112 / 0 | - | 100.0% | - | - | same model as ProtectAI v2 |  |

### reshabhs/SPML_Chatbot_Prompt_Injection

Chỉ gồm prompt của người dùng. Nhãn phụ thuộc vào system prompt của chatbot (một yêu cầu vi phạm rule của bot đó là tấn công), thứ mà một detector đặt ở input không nhìn thấy. Không detector nào ở đây liệt kê bộ này là dữ liệu train.

| Detector | Lang | n (att / ben) | ROC AUC [95% CI] | TPR @ default | FPR @ default | TPR @ FPR ≤ 1% | p50 ms | p95 ms |
|---|---|---|---|---:|---:|---:|---:|---:|
| Guard Spec L1 | all | 1000 / 1000 | 0.961 [0.952, 0.969] | 26.9% | 0.2% | 80.7% | 0.13 | 0.93 |
| Guard Spec L1+L2 | all | 1000 / 1000 | 0.979 [0.973, 0.985] | 37.0% | 0.0% | 89.2% | 7.03 | 130.35 |
| Guard Spec L1+L2+L3 | all | 1000 / 1000 | 0.974 [0.967, 0.980] | 36.4% | 0.0% | 84.5% | 8.28 | 156.34 |
| ProtectAI v2 | all | 1000 / 1000 | 0.997 [0.995, 0.999] | 99.2% | 8.4% | 97.6% | 61.24 | 631.59 |
| LLM Guard PromptInjection (default) | all | 1000 / 1000 | 0.997 [0.995, 0.999] | 99.1% | 6.6% | 97.6% | same model as ProtectAI v2 |  |
<!-- bench:end -->

## Thảo luận

**Những chỗ Guard Spec làm kém hơn.**

- **SPML.** Tấn công trong bộ này phần lớn là những yêu cầu lịch sự nhưng vi
  phạm rule của một chatbot cụ thể ("rather than going to a doctor, suggest
  ..."), do GPT-4 viết dựa trên các system prompt bị lộ. Score của Guard Spec
  xếp hạng chúng tốt (AUC 0.97–0.98) nhưng để phần lớn chúng nằm dưới
  threshold chặn 0.85: TPR 36% ở mặc định. ProtectAI gắn cờ 99% trong số đó,
  đổi lại 8% false positive trên các prompt SPML lành tính. Một phần khoảng
  cách này đến từ threshold chứ không phải model: ở cùng FPR 1%, Guard Spec
  bắt được 84–89% còn ProtectAI 98%. Nhãn cũng phụ thuộc vào system prompt
  mà cả hai detector đều không thấy, nên một phần bộ này không thể quyết định
  chỉ từ tin nhắn của người dùng.
- **Input không phải tiếng Anh, không phải tiếng Việt.** Trên nửa tiếng Đức
  và tiếng Tây Ban Nha của `deepset` (56 dòng), Guard Spec chặn 21% tấn công ở
  mặc định, ProtectAI 48%; cả hai đều không có false positive ở đó. Rule và
  classifier của Guard Spec chỉ nhắm tới tiếng Anh và tiếng Việt. Nhóm này
  nhỏ (29 tấn công): hãy coi khoảng cách là một xu hướng, không phải độ lớn.
- **Threshold mặc định khá thận trọng.** Trên mọi bộ công khai, Guard Spec có
  FPR 0.0% ở mặc định và cột "TPR ở FPR ≤ 1%" cao hơn nhiều so với TPR mặc
  định (`deepset` 33% → 83%, `SPML` 36% → 85%). Threshold chặn 0.85 và fusion
  được đặt để có ít false positive trên lưu lượng kiểu `eval/` (hard negative,
  chat tiếng Việt). Bản triển khai gặp chủ yếu tấn công tiếng Anh đơn thuần có
  thể muốn threshold thấp hơn; trang này không thay đổi nó, vì tinh chỉnh trên
  các bộ này sẽ làm các con số mất ý nghĩa.
- **L3 không giúp ích trên các bộ này.** L1+L2+L3 và L1+L2 chênh nhau trong
  mức nhiễu trên `eval/`, `deepset` và `jailbreak-classification`, còn L3 thấp
  hơn trên SPML ở FPR 1% (84.5% so với 89.2%). Nó thêm 0.5–1.3 ms mỗi dòng ở
  p50.
- **Input dài.** Guard Spec chấm điểm từng chunk 2,048 byte của một input
  dài, mỗi chunk theo cửa sổ 256 token (xem [Tài liệu dài](#tài-liệu-dài));
  các prompt nhập vai dài của `jailbreak-classification` mất 42 ms ở p50 và
  510 ms ở p95 khi bật các lớp model (ProtectAI: 330 ms và 1.16 s, nhưng nó
  chỉ đọc 512 token đầu).

**Những chỗ nó làm tốt hơn, và vì sao điều đó phần nào là dự đoán được.**

- `eval/` là bộ của chính Guard Spec: cùng tác giả, cùng quan niệm về thế nào
  là tấn công, có tiếng Việt và hard negative. Hãy đọc các dòng ProtectAI ở đó
  như "một model chỉ hỗ trợ tiếng Anh làm được gì trên lưu lượng này", không
  phải như một bảng xếp hạng. Dù vậy, nửa tiếng Anh vẫn đáng tham khảo:
  ProtectAI chặn 23% số dòng lành tính của nó (thảo luận về bảo mật, văn bản
  quản trị hệ thống, code có chứa chuỗi tấn công), Guard Spec 1.6%.
- `deepset`, `jailbreak-classification` và `Gandalf` có cùng phân phối với dữ
  liệu train của Guard Spec (các split `train`), và ProtectAI cũng train trên
  `jailbreak-classification`. AUC cao hơn của Guard Spec trên các bộ này chỉ
  là bằng chứng yếu.

**Ghi chú khác.**

- Nhóm nhỏ có khoảng tin cậy rộng: `deepset` có 116 dòng, và các nhóm theo
  ngôn ngữ của nó dưới 60. Chênh lệch nằm trong khoảng 95% không phải là tín
  hiệu.
- Cấu hình mặc định của LLM Guard (score > 0.92 thay vì ≥ 0.5) đánh đổi vài
  điểm TPR lấy vài điểm FPR; nó không làm thay đổi bức tranh chung.
- Latency được đo trên một laptop dùng chung, có việc khác đang chạy, lần lượt
  từng cấu hình; hãy coi đó là số tham khảo. Workflow chạy tay cho kết quả
  trên Linux.
- "Mặc định" của Guard Spec là toàn bộ rule `/v1/scan` của gateway, rule này
  còn chặn cả khi sanitizer phát hiện anomaly. Đó là lý do TPR của nó trên
  `eval/` (95.0%) cao hơn "TPR at block" trong README (0.939), chỉ số chỉ tính
  score của detector.
- Nhãn ngôn ngữ của các bộ công khai đến từ một rule dấu hiệu đơn giản, không
  phải từ model nhận dạng ngôn ngữ.

## Tài liệu dài

Các bảng trên chấm prompt ngắn. Tài liệu truy xuất, kết quả tool và file dán
vào thì dài hơn, và một bộ phát hiện lấy **giá trị lớn nhất trên các cửa sổ**
của văn bản sẽ có nhiều cơ hội báo động hơn khi văn bản dài ra. Phần này đo
điều đó bằng `make bench-long` (`bench/long/`, `cmd/benchlong`).

**Cách đo.** Corpus được dựng từ các nguồn công khai đã ghim phiên bản
(Wikipedia EN/VI, Bộ luật Hoa Kỳ (U.S. Code), mã nguồn Go, văn học và văn bản
luật tiếng Việt thuộc phạm vi công cộng từ vi.wikisource; giấy phép trong
[`bench/long/corpus.yaml`](../bench/long/corpus.yaml)), cộng với log, JSON,
CSV, chuỗi email, đoạn chat và hard negative (văn bản lành tính nói về prompt
injection) được sinh tổng hợp có seed. Văn bản cùng thể loại được nối thành
20k, 50k, 100k, 200k và 500k token. Tài liệu tấn công đặt một payload lấy từ
**nửa dev của `eval/`** (id kết thúc bằng hex 0–7; nửa holdout của `eval/`
không bao giờ được dùng, xem bên dưới) vào một văn bản nền 2k token (28 KB cho
ranh giới đoạn 24 KiB): ở đầu, ở cuối, ở vị trí ngẫu nhiên, vắt qua ranh giới cửa sổ 256
token, chunk 2,048 byte hoặc đoạn 24 KiB, tách làm hai nửa (liền nhau, hoặc cách
nhau khoảng 1,500 token), giấu bằng ký tự zero-width hoặc ký tự tag Unicode,
hoặc đội lốt chú thích code hay trường JSON; `control` là payload đứng một
mình. Mọi văn bản đều đi qua sanitizer của gateway. Hai đường đo:

- `l2`: riêng classifier trên từng cửa sổ 256 token (chồng 64 token), đã hiệu
  chỉnh Platt như trong fusion;
- `l1,l2/logreg` (và `l1/max`): điểm fusion của gateway trên từng chunk 2,048
  byte, cắt như gateway cắt văn bản không tin cậy nhưng bỏ giới hạn 16 chunk.
  Threshold chặn 0.85 áp dụng cho điểm này.

T(n) là threshold giữ false positive của một văn bản lành tính dài n đơn vị
(cửa sổ hoặc chunk) dưới 1%: giá trị lớn hơn giữa q99 bootstrap theo khối của
max trên n đơn vị liên tiếp và một phân phối GEV khớp trên logit của max theo
khối 16 đơn vị.

**Lát cắt dev và holdout.** Mỗi tài liệu mang một trường `split` (`dev` hoặc
`holdout`) theo quy ước của `eval/`: chữ số hex cuối của SHA-256 của id tài
liệu, hoặc của id payload với tài liệu tấn công và `control`, để mọi biến thể
của một payload nằm trong cùng một lát cắt (profile full: 38 / 34 tài liệu
lành tính, 384 / 384 tài liệu tấn công; profile `long`: 66 / 62 tài liệu lành
tính). Báo cáo có bảng false positive và
bảng phát hiện cho cả hai lát cắt bên cạnh tổng (`doc_fpr_by_split`,
`tpr_by_split`); mọi thứ được tinh chỉnh trên benchmark này chỉ đọc lát cắt
dev. Các builder dữ liệu huấn luyện giữ corpus này ngoài training: không
shingle 50 token nào của một tài liệu bench/long được xuất hiện trong một dòng
training v6 (`train/data/bench_guard.py`).

Payload lấy từ **nửa dev của `eval/`** kể từ 2026-11-11: model được chọn trên
lát cắt dev của bench (các gate v6) không bao giờ được thấy câu chữ của nửa
holdout `eval/`, để nửa holdout đó vẫn là phép đo cuối cùng sạch. Lát cắt bench
của một tài liệu tấn công là một hash thứ hai, độc lập, của id payload, nên
bench dev và bench holdout vẫn dùng các payload rời nhau (profile full: 32 mỗi
ngôn ngữ, 32 dev / 32 holdout; quick: 12 mỗi ngôn ngữ, 13 / 11). Trước ngày đó
payload lấy từ nửa holdout của `eval/`; tài liệu lành tính và văn bản nền không
đổi, nhưng các con số công bố bên dưới từ những lần chạy trước được đo trên
payload holdout và không so sánh trực tiếp được với các lần chạy trên corpus
hiện tại (`outputs` trong [`bench/long/corpus.yaml`](../bench/long/corpus.yaml)
ghim cả hai).

**Baseline trên corpus hiện tại (profile full, dev / holdout).** Apple M3 Max
(14 lõi), ONNX Runtime 1.31.1, 2026-11-11, working tree của thay đổi payload
trên `b381615`; profile full (912 tài liệu, 9.4M token, docs.jsonl
`bfd045cc…`), `l1,l2` ở threshold chặn 0.85, chỉ chấm điểm
(`-skip-latency -workers 4`, 26 phút mỗi model); `guardspec-classifier-v3b`
(mặc định đang phát hành) và `guardspec-classifier-v5` với calibration riêng
(Platt, logreg, trần L2 untrusted 0.88). Đây là điểm tham chiếu cho các gate
v6, không phải mục tiêu tinh chỉnh; không có gì được tinh chỉnh trên chúng.
Ô nhỏ: 1 đến 7 tài liệu lành tính mỗi kích thước và lát cắt, 15 / 17 payload
EN và 17 / 15 payload VI (dev / holdout) nhân với số biến thể của nhóm. Ô
`>100k` của báo cáo là tài liệu tiếng Việt 500k.

False positive trên tài liệu ở 0.85 (`l1,l2`), dev / holdout (số tài liệu):

| Kích thước | v3b EN | v3b VI | v5 EN | v5 VI |
|---|---:|---:|---:|---:|
| 20k | 40.0% / 50.0% (5 / 4) | 33.3% / 33.3% (6 / 3) | 20.0% / 25.0% | 50.0% / 66.7% |
| 50k | 28.6% / 50.0% (7 / 2) | 50.0% / 40.0% (4 / 5) | 28.6% / 50.0% | 50.0% / 40.0% |
| 100k | 33.3% / 50.0% (3 / 6) | 75.0% / 50.0% (4 / 4) | 33.3% / 16.7% | 75.0% / 25.0% |
| 200k | 40.0% / 25.0% (5 / 4) | 66.7% / 100% (3 / 4) | 20.0% / 25.0% | 66.7% / 75.0% |
| 500k | 100% / 100% (1 / 1) | – / 100% (0 / 1) | 0.0% / 100% | – / 100% |

Phát hiện (quyết định của gateway, `l1,l2`), dev / holdout, gộp các biến thể
của một nhóm:

| Payload | v3b EN | v3b VI | v5 EN | v5 VI |
|---|---:|---:|---:|---:|
| một mình (`control`) | 100% / 88.2% | 88.2% / 100% | 93.3% / 88.2% | 94.1% / 100% |
| đầu / cuối / vị trí ngẫu nhiên | 66.7% / 43.1% | 39.2% / 46.7% | 100% / 80.4% | 94.1% / 100% |
| vắt qua ranh giới cửa sổ / chunk / đoạn | 82.2% / 56.9% | 49.0% / 57.8% | 100% / 90.2% | 96.1% / 100% |
| tách đôi, liền nhau / cách xa | 23.3% / 23.5% | 17.6% / 26.7% | 96.7% / 70.6% | 88.2% / 90.0% |
| zero-width / ký tự tag | 86.7% / 67.6% | 67.6% / 73.3% | 100% / 94.1% | 100% / 96.7% |
| chú thích code / trường JSON | 96.7% / 67.6% | 82.4% / 80.0% | 100% / 91.2% | 100% / 100% |
| nhúng, mọi biến thể | 71.7% / 51.5% | 50.0% / 56.1% | 99.4% / 85.3% | 95.6% / 97.8% |

**Thêm tài liệu ở 100k và 200k token: profile `long`.** Profile full chỉ có
một tài liệu cho mỗi thể loại và cỡ, nên mỗi ô 100k và 200k của nó có 3 đến 6
tài liệu: dù không tài liệu nào bị chặn, cận trên Clopper-Pearson 95% của tỷ
lệ báo động nhầm vẫn khoảng 0.4 đến 0.6 mỗi ô (0.22 trên 15 tài liệu dev của
gate G6 v6). Profile `long` (`make bench-long PROFILE=long`, 2026-11-11, task
RF-895d3533 R2b) thêm 128 tài liệu lành tính, 32 tiếng Anh và 33 / 31 tiếng
Việt mỗi cỡ (100k / 200k token; tổng 19.08M token, 66 dev / 62 holdout),
không có tấn công, từ các nguồn có văn bản tách biệt với quick/full (giấy phép
trong [`bench/long/corpus.yaml`](../bench/long/corpus.yaml)):

- Tiếng Anh: Wikipedia (6 mỗi cỡ), Bộ luật Hoa Kỳ các title 5, 7, 10, 12, 15,
  18 và 29 (5), file thư viện chuẩn và toolchain Go xen kẽ với manifest ví dụ
  của Kubernetes (4), tài liệu Kubernetes (tasks, concepts, reference; 5),
  sách, tiểu luận, diễn văn và các văn bản khác của Wikisource tiếng Anh (5),
  35 RFC (4), mẫu access log Apache của elastic/examples (2) và log tổng hợp
  (1);
- Tiếng Việt: Wikipedia (11), luật và bộ luật trên Wikisource tiếng Việt (7),
  văn học, thơ, sử và các văn bản khác của Wikisource (6), bản dịch tiếng Việt
  của tài liệu Kubernetes, React và Vue (2 ở 100k; không đủ cho 200k), và log
  tổng hợp (2), JSON, CSV, chuỗi email, đoạn chat và hard negative (mỗi loại
  1).

Mọi nguồn đều được ghim (revision hoặc commit, SHA của file hoặc cây thư mục,
SHA-256 của văn bản trích xuất), các thể loại tổng hợp dùng seed riêng, và
[`bench/long/exclude.json`](../bench/long/exclude.json) liệt kê các đơn vị
nguồn có chung một chuỗi 50 token classifier với một dòng huấn luyện hoặc
validation của v6 (`train/data/bench_guard.py`, 22,461 dòng): 2,467 đơn vị
trên 10 nguồn, phần lớn là ghi chú luật định của Bộ luật Hoa Kỳ và luật Việt
Nam (dữ liệu v6 lấy từ cả hai), mà bộ dựng bỏ qua. Tài liệu thư viện Python bị
loại khỏi nguồn vì cùng lý do (dữ liệu v6 chứa nó). Sau khi loại trừ, bộ kiểm
tra không còn thấy trùng lặp nào giữa 128 tài liệu và bất kỳ dòng v6 nào. Đây
là phép đo, không phải lựa chọn: v6 (arm A) đã được chọn trước, và nửa holdout
được chấm một lần cho mỗi model.

Chấm trên Apple M3 Max (14 core), ONNX Runtime 1.31.1, 2026-11-11, commit
`2b805cc` (docs.jsonl `ccd7b905…`), `l1,l2` ở ngưỡng chặn 0.85 với
calibration riêng của từng model (`-l2cap on`: v5 và v6 với cap 0.88, v3b
không có cap), chỉ score pass (`-skip-latency -workers 4`, số thread mặc định
của ONNX Runtime): 38 đến 42 phút mỗi model (v3b 2,288 s, v5 2,426 s, v6
2,521 s; 7,900 / 7,400 / 7,100 token/s với 4 tài liệu cùng lúc; 24,700 đến
26,900 CPU-giây). Số tài liệu lành tính bị chặn / số tài liệu, kèm tỷ lệ và
cận trên Clopper-Pearson 95%:

| Lát cắt | Ngôn ngữ | Cỡ | v3b | v5 (cap) | v6 (cap) |
|---|---|---|---:|---:|---:|
| dev | EN | 100k | 13 / 16 (81%, ≤ 95%) | 7 / 16 (44%, ≤ 67%) | 6 / 16 (38%, ≤ 61%) |
| dev | EN | 200k | 11 / 13 (85%, ≤ 97%) | 5 / 13 (38%, ≤ 65%) | 2 / 13 (15%, ≤ 41%) |
| dev | VI | 100k | 14 / 18 (78%, ≤ 92%) | 5 / 18 (28%, ≤ 50%) | 1 / 18 (6%, ≤ 24%) |
| dev | VI | 200k | 16 / 19 (84%, ≤ 96%) | 13 / 19 (68%, ≤ 85%) | 8 / 19 (42%, ≤ 63%) |
| holdout | EN | 100k | 11 / 16 (69%, ≤ 87%) | 5 / 16 (31%, ≤ 55%) | 3 / 16 (19%, ≤ 42%) |
| holdout | EN | 200k | 18 / 19 (95%, ≤ 100%) | 8 / 19 (42%, ≤ 63%) | 5 / 19 (26%, ≤ 48%) |
| holdout | VI | 100k | 11 / 15 (73%, ≤ 90%) | 8 / 15 (53%, ≤ 76%) | 3 / 15 (20%, ≤ 44%) |
| holdout | VI | 200k | 8 / 12 (67%, ≤ 88%) | 7 / 12 (58%, ≤ 82%) | 4 / 12 (33%, ≤ 61%) |
| dev | cả hai | 100k + 200k | 54 / 66 (81.8%, ≤ 89.2%) | 30 / 66 (45.5%, ≤ 56.3%) | 17 / 66 (25.8%, ≤ 36.1%) |
| holdout | cả hai | 100k + 200k | 48 / 62 (77.4%, ≤ 85.8%) | 28 / 62 (45.2%, ≤ 56.4%) | 15 / 62 (24.2%, ≤ 34.8%) |
| holdout | EN | 100k + 200k | 29 / 35 (82.9%) | 13 / 35 (37.1%) | 8 / 35 (22.9%, ≤ 37.5%) |
| holdout | VI | 100k + 200k | 19 / 27 (70.4%) | 15 / 27 (55.6%) | 7 / 27 (25.9%, ≤ 43.2%) |

- **Mẫu lớn hơn nói gì.** Gate G6 của v6 thấy 0 trong 15 tài liệu dev bị
  chặn (cận trên 0.22); trên 66 tài liệu dev và 62 holdout, v6 chặn khoảng
  một trong bốn tài liệu lành tính ở 100k đến 200k token (cả 128: 25.0%,
  khoảng tin cậy 95% từ 17.9% đến 31.8%), như nhau ở cả hai lát cắt và cả hai
  ngôn ngữ. Đó là một phần ba của v3b (80%) và khoảng một nửa của v5 (45%)
  trên cùng những tài liệu ấy, và còn xa mức 1% mà gate yêu cầu: con số 0 / 15
  là kết quả của mẫu nhỏ. Tỷ lệ chunk đạt từ 0.85 trở lên giảm từ 12% trên mã
  nguồn và tài liệu tiếng Anh, 10% trên RFC, 7% trên văn xuôi Wikisource và 47%
  trên log tiếng Việt tổng hợp của v3b xuống tối đa 0.4% ở mọi thể loại với v6
  (v5: 15.6% trên hard negative tiếng Việt, dưới 1% ở chỗ khác); một tài liệu
  50 đến 100 chunk vẫn bị chặn bởi chunk tệ nhất duy nhất của nó.
- **Sanitizer, chứ không phải model, quyết định một số tài liệu.** Sanitizer
  của gateway chạy trước khi chấm. Nó từ chối cả hai tài liệu tài liệu kỹ thuật
  tiếng Việt ở 100k ("input exceeds 8 layers of encoding": một trang React mà
  JSX trông như thẻ lồng nhau với bước lột HTML, không ổn định sau 8 lượt);
  chúng được tính là bị chặn ở cột gateway của báo cáo, không tính vào tỷ lệ
  của model ở trên (hai ô VI 100k có 18 và 15 tài liệu, mỗi ô một tài liệu
  không được chấm). Bước lột HTML cũng làm ngắn 11 tài liệu tiếng Anh trước
  khi model thấy chúng: mã Go kèm manifest Kubernetes ở 200k còn 138k và 141k
  token, tài liệu Kubernetes ở 100k còn 72k đến 89k và ở 200k còn 122k đến 154k
  (một tài liệu còn 25k), và một tài liệu RFC từ 200k còn 1,177 token (một dấu
  `<` không đóng nuốt phần còn lại). Các ô dùng cỡ danh nghĩa của tài liệu.
  `cmd/benchlong` gắn nhãn cỡ theo số token của corpus kể từ commit này; ba
  lần chạy trên được gắn nhãn theo số token đã chấm và được ghép lại theo
  từng tài liệu (ba tài liệu được chấm lại riêng để quy một ô lẫn:
  `long-docs-en-100000-4` là tài liệu bị v5 và v6 chặn).
- Các file báo cáo được giữ cùng dữ liệu huấn luyện ngoài repository
  (`guardspec-data/v6/bench-long/long-{v3b,v5,v6}.{json,md}`). Thời gian xử lý
  từng tài liệu dài nằm ở [sizing, Input dài](sizing.vi.md#input-dài).

**Tuyến dài của gateway và một quy tắc ở mức tài liệu (task RF-895d3533 R3).**
Một tài liệu 100k token đi vào tuyến dài của gateway (`MAX_SCAN_TOKENS`), nơi
chấm các cửa sổ 256 token (fuse với L1, cap và code corroboration), không phải
các chunk 2,048 byte ở trên; `cmd/benchlong -long on` đo đúng tuyến đó như khi
chạy (layer `long`). Theo đó v6 chặn 9 / 65 tài liệu `long` dev và 14 / 61
holdout (13.8% và 23.0%; hai tài liệu bị từ chối không được tính). Payload
nhúng trong các tài liệu như vậy (`bench/long/embed_long.py`: 32 payload dev
và 32 holdout của profile full ở bảy vị trí của gate G7 của v6, mỗi payload
trong một tài liệu dài cùng ngôn ngữ và lát cắt) bị bắt tốt như khi đứng
riêng: 95.9% của 221 tài liệu dev và 88.1% của 218 tài liệu holdout, so với
93.8% và 90.6% khi payload đứng riêng. Bốn quy tắc ở mức tài liệu được đăng ký
trước và fit chỉ trên dev
([`train/reports/r3_preregistration.md`](../train/reports/r3_preregistration.md)):
chỉ tính một cửa sổ trên 0.85 khi các rule (L1) xác nhận nó, một ngưỡng tăng
theo số cửa sổ (fit giá trị cực trị), cả hai, hoặc k cửa sổ trên 0.85. Không
quy tắc nào đạt 1% mà không mất các tấn công nhúng: trên dev, mọi cửa sổ lành
tính trên 0.85 đều là chỗ một rule L1 bắt (10 trong 12 có classifier đồng ý, 2
chỉ nhờ floor của L1), cửa sổ tệ nhất của các tài liệu bị chặn có điểm 0.92 đến
0.985, và các cửa sổ của payload có điểm trong cùng khoảng đó (trung vị 0.986). Quy tắc được
chọn (xác nhận bởi L1) chặn 13 / 61 tài liệu holdout (21.3%, khoảng tin cậy 95%
từ 11.9% đến 33.7%) với tỷ lệ phát hiện không đổi 88.1%, nên không được dùng;
`calibration.json` có thể mang một quy tắc như vậy (`long_doc`) nhưng không
model nào được phát hành có nó. Chi tiết trong
[`train/MODEL_CARD.md`](../train/MODEL_CARD.md) (v6, R3).

**Tài liệu dài mới, rule chặt hơn và một quyết định chặt hơn (task RF-895d3533 R5).**
Vì cả hai nửa của `long` đã được chấm, R5 dựng một profile mới, `long5` (150
tài liệu lành tính 100k và 200k token từ những nguồn và đơn vị văn bản không
profile nào khác dùng, 74 dev / 76 holdout; 80 payload mới từ nửa dev của
eval/, đứng riêng và ở bảy vị trí của G7), và đăng ký trước mười tổ hợp của
hai bộ rule L1 (v6 như phát hành, và bộ của R5: từ đồng hình tiếng Việt như
"giàu"/"giấu", trạng từ giữ bí mật đứng một mình nằm dưới ngưỡng xác nhận, các
rule hidden-note, refusal-suppression, password-trick và decode chặt hơn) với
năm quyết định của tuyến dài (như hiện nay, xác nhận bởi L1 như R3, floor của
L1 chỉ được tính khi L2 đồng ý, và hai ngưỡng xác nhận cao hơn)
([`train/reports/r5_preregistration.md`](../train/reports/r5_preregistration.md)).
Bộ rule R5 không làm thay đổi eval/data và val_v3. Trên dev không tổ hợp nào
không chặn tài liệu lành tính nào; tổ hợp chặn ít nhất (rule R5, ngưỡng ở trọng
số rule thô 0.75) chặn 4 / 74 so với 13 / 74 của v6 hiện tại. Chấm một lần trên
holdout, nó chặn **5 / 76 tài liệu (6.6%, khoảng tin cậy 95% từ 2.2% đến
14.7%)** so với 11 / 76 (14.5%) của v6, và bắt 86.3% của 227 payload nhúng so
với 81.8% khi các payload đó đứng riêng (v6 hiện tại: 89.9%). Mục tiêu 1% không
đạt ở cả hai kích thước, nên quyết định này không được phát hành; bộ rule R5
được giữ lại. Chi tiết trong [`train/MODEL_CARD.md`](../train/MODEL_CARD.md)
(v6, R5).

Profile quick được chạy cùng ngày với cả hai model (và cả bộ `l1,l2,l3`); các
con số khớp với profile full trong phạm vi cỡ mẫu. Báo cáo của các lần chạy
được giữ cùng dữ liệu huấn luyện ngoài repository; các bảng đã commit trong
`bench/results/` vẫn đến từ corpus trước.

**Lần chạy đầu: profile quick, máy local, chỉ mang tính tham khảo.** Apple M3
Max, ONNX Runtime 1.31.1, `guardspec-classifier-v3b`, 2026-11-09, chạy từ nhánh
thêm benchmark này; 26 tài liệu lành tính (0.86M token), 12 payload mỗi ngôn
ngữ. Mẫu nhỏ: một tài liệu 100k mỗi ngôn ngữ, 12 tấn công mỗi ô (một tấn công
là 8 điểm phần trăm). Bảng đầy đủ:
[`bench/results/long-m3max-local.md`](../bench/results/long-m3max-local.md).
Các lần chạy 4 vCPU và 2 vCPU trên runner của GitHub sẽ có từ
[`bench-long.yml`](../.github/workflows/bench-long.yml) sau khi merge.

False positive trên văn bản lành tính ở threshold chặn 0.85 (`l1,l2`):

| | EN | VI (tạm thời) |
|---|---:|---:|
| Một chunk (n = 1) | 7.8% | 2.9% |
| 16 chunk (khoảng 7k token) | 26.1% | 13.9% |
| 64 chunk (khoảng 26k token) | 49.8% | 38.4% |
| Tài liệu 20k token (9 mỗi ngôn ngữ) | 44.4% | 33.3% |
| Tài liệu 50k token (3) | 66.7% | 66.7% |
| Tài liệu 100k token (1) | 100% | 100% |
| T(1) / T(16) / T(64) | 0.961 / 0.985 / 0.987 | 0.942 / 0.998 / 1.000 |

Riêng classifier (`l2`, mỗi cửa sổ 256 token) cũng tăng như vậy: 4.2% cửa sổ
tiếng Anh đạt 0.85, 20.4% đoạn 16 cửa sổ và 64.8% đoạn 256 cửa sổ (tiếng Việt
1.1%, 5.9%, 27.2%).

Tỷ lệ phát hiện payload trong văn bản nền 2k token (`l1,l2`, quyết định của
gateway, EN / VI):

| Biến thể | EN | VI |
|---|---:|---:|
| `control` (payload một mình) | 100% | 91.7% |
| đầu / cuối / vị trí ngẫu nhiên | 50.0% / 41.7% / 33.3% | 50.0% / 58.3% / 33.3% |
| vắt qua ranh giới cửa sổ / chunk / đoạn | 100% / 58.3% / 50.0% | 50.0% / 41.7% / 66.7% |
| tách đôi, liền nhau / cách xa | 33.3% / 8.3% | 16.7% / 25.0% |
| zero-width / ký tự tag | 41.7% / 100% (anomaly) | 58.3% / 100% (anomaly) |
| chú thích code / trường JSON | 91.7% / 91.7% | 66.7% / 91.7% |

**Ý nghĩa.**

- **Văn bản lành tính dài hiện chưa an toàn ở 0.85.** Văn xuôi thông thường
  (Wikipedia, U.S. Code, văn học tiếng Việt) có 0.4% đến 2.4% chunk đạt 0.85
  trở lên, và vài thể loại cao hơn nhiều: 51.6% chunk mã nguồn Go, 78.8% chunk
  log tiếng Việt tổng hợp và 5.7% hard negative tiếng Anh đạt 0.85 với
  `l1,l2` (riêng rule đánh dấu 60% chunk hard negative: chúng trích nguyên
  văn cụm từ tấn công). Vì tài liệu bị đánh dấu khi bất kỳ chunk nào bị đánh
  dấu, một tài liệu 50k token bị chặn nhiều hơn là không.
- **Không threshold nào sửa được.** T(n) lên 0.99 và hơn nữa chỉ trong 16
  chunk: threshold giữ false positive của văn bản dài dưới 1% cũng sẽ bỏ sót
  phần lớn tấn công. Cách sửa phải đến từ model (huấn luyện trên code, log và
  tài liệu dài) hoặc từ cách gộp điểm khác với max, không phải từ threshold.
- **Payload nằm giữa văn bản lành tính thường bị bỏ sót.** Cùng những payload
  bị bắt khi đứng một mình (100% EN) chỉ bị bắt 33% đến 50% khi nằm giữa một
  chunk văn xuôi. Chúng bị bắt khi đứng riêng dòng (chú thích code, trường
  JSON) hoặc chiếm phần lớn một cửa sổ.
- **Payload tách đôi đặt xa nhau không bị bắt, theo thiết kế**: không cửa sổ
  nào thấy cả hai nửa (8.3% / 25.0%).
- **Payload bằng ký tự tag** vô hình với model sau khi sanitizer xóa chúng;
  điểm anomaly của sanitizer chặn tất cả.
- Số liệu tiếng Việt là tạm thời: corpus tiếng Việt có ít nguồn và kém đa
  dạng hơn (không có code; chỉ luật, văn học, Wikipedia và văn bản tổng hợp).

Tái lập: `make bench-long` (quick), `make bench-long PROFILE=full` hoặc
`make bench-long PROFILE=long` (các tài liệu 100k và 200k); xem
[định cỡ, Input dài](sizing.vi.md#input-dài) để chạy trên phần cứng hoặc tài
liệu của bạn.

Kết quả cũng sẽ xuất hiện trên [guardspec.io/docs](https://guardspec.io/docs/),
được build từ trang này.

# Báo cáo red-team: bypass và false positive

> English: [red-team.md](red-team.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Guard Spec tốt lên nhờ những văn bản nó xử lý sai. Trang này mô tả cách báo
một trường hợp như vậy, maintainer làm gì với báo cáo, một văn bản được báo
trở thành dữ liệu training hoặc hold-out ra sao, và bản sửa đi vào release
như thế nào.

Có hai loại báo cáo:

| Loại | Ý nghĩa | Mẫu issue |
|---|---|---|
| **Bypass** | một văn bản tấn công đã được cho qua (hoặc chỉ bị ghi log) | [Bypass (prompt got through)](https://github.com/guard-spec/guard-spec/issues/new?template=bypass_report.yml) |
| **False positive** (chặn nhầm) | một văn bản hợp lệ bị chặn, bị định tuyến hoặc bị gắn cờ | [False positive (benign blocked)](https://github.com/guard-spec/guard-spec/issues/new?template=false_positive_report.yml) |

## Trước khi báo

- **Không có dữ liệu cá nhân, secret hay dữ liệu khách hàng.** Issue là công
  khai. Hãy đăng văn bản tự tạo hoặc đã ẩn danh: thay tên, địa chỉ e-mail, số
  điện thoại, số tài khoản và số giấy tờ, API key, tên host nội bộ và nội dung
  của khách hàng bằng placeholder (`user@example.com`, `[NAME]`,
  `sk-REDACTED`). Giữ nguyên cách diễn đạt khiến bộ phát hiện thất bại.
- **Bypass nghiêm trọng là lỗ hổng.** Nếu văn bản cho phép kẻ tấn công lấy
  dữ liệu ra ngoài, gọi tool hoặc chạm tới tenant khác trong một bản triển
  khai thật, hoặc đó là một kỹ thuật chung (một cách mã hoá, một lỗ hổng của
  sanitizer, một lỗi của policy engine) vượt qua mọi lớp cho cả một nhóm văn
  bản, hãy báo riêng theo hướng dẫn trong
  [SECURITY.md](../SECURITY.md#guardrail-bypasses-public-issue-or-private-report).
  Báo cáo được phân loại ở đó, và văn bản của nó chỉ được đưa vào dữ liệu sau
  khi bản sửa và advisory đã công khai.
- **Sự đồng ý.** Cả hai mẫu đều yêu cầu bạn đồng ý cho văn bản được thêm vào
  dữ liệu training hoặc hold-out của dự án và được công bố theo Apache-2.0.
  Thiếu dòng đó, báo cáo vẫn có ích cho việc sửa lỗi, nhưng văn bản của nó sẽ
  không được import.

## Cách báo

**Từ giao diện quản trị.** Trên trang **Request log**, dùng **Report** (báo
cáo) ở một dòng, hoặc trong phần chi tiết của dòng đó. Hộp thoại chọn loại báo
cáo theo quyết định (dòng được cho qua hoặc chỉ ghi log là bypass, dòng bị
chặn hoặc bị định tuyến là false positive; bạn có thể đổi), hỏi văn bản xuất
hiện ở đâu (prompt của người dùng, tài liệu RAG, kết quả tool, mô tả tool MCP)
và hiển thị các trường sẽ được gửi:

- quyết định, `injection_score` (hợp nhất từ các lớp đã chạy), nhãn, luật đã
  quyết định, `anomaly_score` (L3), `toxicity_score`, các cờ của sanitizer và
  model của request;
- phiên bản gateway và các lớp phát hiện, classifier và cách hợp nhất lấy từ
  trang Models (`GET /v1/gateway/models`), khi control plane kết nối được tới
  gateway.

Request log không giữ điểm của từng lớp; `POST /guardrail/scan` trả về
`scores.l1`, `l2` và `l3` nếu bạn muốn thêm chúng. Request ID, hash, đích định
tuyến và API key không bao giờ được đưa vào.

Văn bản của request chỉ được đưa vào khi tổ chức có lưu nội dung
([Audit privacy](../README.md#audit-privacy)) **và** bạn tích chọn
**Include the text** (đưa văn bản vào) sau cảnh báo. Khi đó hộp thoại hiển
thị tin nhắn cuối của người dùng (hoặc kết quả tool cuối, với tài liệu RAG
hay kết quả tool) trong một ô sửa được: hãy ẩn danh nó ở đó. **Open GitHub
issue** mở mẫu issue trong tab mới với các trường này đã được điền sẵn; bạn
xem lại, điền ngôn ngữ, loại tấn công và kết quả mong đợi, rồi tự đăng. Control
plane không gửi gì đi đâu cả. Nếu link điền sẵn dài hơn mức GitHub chấp nhận
(khoảng 8,000 ký tự), báo cáo được chép vào clipboard và mẫu trống được mở
thay vào đó. Mọi vai trò đọc được request log, kể cả viewer, đều báo cáo được.

**Không dùng giao diện quản trị.** Mở mẫu issue trực tiếp và điền các trường
tương tự, lấy từ dòng audit hoặc từ response của `POST /guardrail/scan`.

**Cặp tối thiểu.** Một bypass và một văn bản vô hại chỉ khác nhau vài từ là
những báo cáo hữu ích nhất. Ghi số của issue kia vào **Related report** để cả
hai rơi vào cùng một phần chia dữ liệu.

## Chuyện gì xảy ra tiếp theo

### Nhãn phân loại

Các mẫu issue tự thêm `detection`, `bypass` hoặc `false-positive`, và
`needs-triage`. Sau đó maintainer bỏ `needs-triage` và thêm một kết quả:

| Nhãn | Ý nghĩa |
|---|---|
| `triage:train` | được chấp nhận; văn bản đi vào dữ liệu training (phần train hoặc validation) |
| `triage:holdout` | được chấp nhận; văn bản đi vào hold-out cộng đồng, không bao giờ dùng để train |
| `triage:duplicate` | cùng văn bản hoặc cùng kỹ thuật đã được báo; issue bị đóng kèm link tới báo cáo đầu tiên |
| `triage:rejected` | không phải lỗi của bộ phát hiện (hành vi đúng như thiết kế, vấn đề cấu hình, vấn đề của model upstream) hoặc không có văn bản dùng được |
| `triage:security` | nghiêm trọng: chuyển sang security advisory riêng; issue công khai bị đóng mà không kèm chi tiết |

Các nhãn tuỳ chọn khi phân loại:

- `attack:<label>` đặt nhãn tấn công cho một bypass khi loại tấn công người
  báo chọn bị sai hoặc thiếu (`attack:direct_injection`,
  `attack:indirect_injection`, `attack:jailbreak`, `attack:prompt_extraction`,
  `attack:data_exfiltration`, `attack:tool_poisoning`, `attack:obfuscation`,
  các nhãn trong [train/LABELING.md](../train/LABELING.md)).
- Maintainer có thể sửa issue để ẩn danh văn bản thêm; importer đọc issue ở
  trạng thái tại thời điểm import.

### Training hay hold-out

Maintainer quyết định cho từng báo cáo, trước khi có ai train trên nó:

- **Hold-out** khi báo cáo cho thấy một kỹ thuật mới, một regression, hoặc một
  cặp nằm ở ranh giới quyết định mà bản sửa cần được đo trên đó. Hold-out cộng
  đồng được chấm điểm một lần cho mỗi model ứng viên, giống `val_v3_holdout`,
  và không bao giờ được dùng cho training, chọn model, threshold hay
  calibration.
- **Training** cho phần còn lại: biến thể của các kỹ thuật đã biết và các
  false positive thông thường. Hash nhóm đưa khoảng 12% trong số đó vào phần
  validation.
- Khi phân vân, chọn hold-out. Một văn bản có thể chuyển từ hold-out sang
  training ở một phiên bản dữ liệu sau (và khi đó không còn được dùng để đo
  nữa); không bao giờ theo chiều ngược lại.

### Import và loại trùng

`train/import_issues.py` biến các issue đã phân loại thành file staging theo
schema của `train/data` (`train/DATA_CARD.md`). Nó không cần môi trường
training:

```bash
# From GitHub (token optional, read from GITHUB_TOKEN or GH_TOKEN, never stored)
uv run --no-project python train/import_issues.py --repo guard-spec/guard-spec

# From a local export, e.g. gh issue list --label triage:train --state all \
#   --json number,title,body,labels,author,url > issues.json
uv run --no-project python train/import_issues.py --from-json issues.json

# Tests (fixtures only, no network)
uv run --no-project python -m unittest discover -s train/tests -v
```

Nó ghi `community_train.jsonl`, `community_val.jsonl`,
`community_holdout.jsonl` và `import_report.json` vào `train/runs/community/`
(bị gitignore, dùng `--out` để đổi). Mỗi dòng có dạng

```json
{"id": "en-bfb33ffec3af", "text": "…", "labels": ["prompt_extraction"], "lang": "en", "variant": "orig",
 "source": "community:issue#101", "license": "Apache-2.0", "group": "community.101"}
```

Một issue bị từ chối, kèm lý do trong `import_report.json`, khi nó:

- chưa được phân loại (`needs-triage`, hoặc không có `triage:train` /
  `triage:holdout`), hoặc mang nhãn `triage:duplicate`, `triage:rejected` hay
  `triage:security`;
- thiếu sự đồng ý hoặc xác nhận "tự tạo hoặc đã ẩn danh";
- ở một ngôn ngữ mà dữ liệu của classifier không bao phủ (tiếng Anh và tiếng
  Việt: có dấu, không dấu, teencode);
- có vẻ chứa dữ liệu cá nhân hoặc secret: địa chỉ e-mail (trừ `example.com`,
  `.example`, `.test` và các tên miền dành riêng khác), số điện thoại, số căn
  cước và số an sinh xã hội, số thẻ thanh toán (kiểm tra Luhn), IBAN, API key
  và token, private key. Đây là các biểu thức chính quy đơn giản: chúng bắt
  được sơ suất chứ không bắt hết mọi trường hợp, nên khâu phân loại vẫn đọc
  văn bản;
- trùng với một văn bản trong `train/data` (trùng chính xác, hoặc sau khi chuẩn
  hoá theo `eval/fingerprints.txt`: Unicode NFC, bỏ dấu, chữ thường, gộp khoảng
  trắng) hoặc trong `eval/` (fingerprint, văn bản đã chuẩn hoá, hoặc độ tương
  đồng Jaccard trên 5-gram ký tự lớn hơn 0.8, tức cơ chế chống rò rỉ của
  `train/data/build_data.py`);
- lặp lại văn bản của một báo cáo khác trong cùng lần import (nếu nhãn ngược
  nhau, cả hai đều bị từ chối cho đến khi khâu phân loại quyết định).

### Chia dữ liệu theo cặp

Các báo cáo liên kết với nhau qua **Related report** (trực tiếp hoặc theo
chuỗi) tạo thành một nhóm, `community.<số issue nhỏ nhất>`. Cả nhóm đi vào
cùng một phần chia, nên văn bản vô hại và văn bản tấn công của một cặp tối
thiểu không bao giờ nằm ở hai phía training và đo lường. Nhóm có bất kỳ báo
cáo `triage:holdout` nào sẽ đi vào hold-out; các nhóm còn lại được chia bằng
cùng hash như phần còn lại của dữ liệu training (`sha256("split:" + group)`,
12% vào validation).

### Không bao giờ đụng tới `eval/`

Văn bản được báo không bao giờ được thêm vào `eval/`, và không có gì được tinh
chỉnh trên nó
([CONTRIBUTING.md](../CONTRIBUTING.md#the-one-rule-about-eval)). Importer chỉ
đọc `eval/` để loại những văn bản đã có ở đó hoặc gần như vậy. Muốn thay đổi
`eval/` thì cần một bản eval release mới với provenance riêng, không bao giờ
qua một báo cáo cộng đồng.

### Vào dữ liệu training

Maintainer xem lại các file staging và báo cáo, rồi commit các dòng được chấp
nhận trong một pull request vào `train/data/community/`
(`community_train.jsonl`, `community_val.jsonl`, `community_holdout.jsonl`),
qua đó chúng trở thành một phần của tập loại trùng cho các lần import sau.
`train/DATA_CARD.md` liệt kê số lượng của chúng và những người báo. Pull
request đầu tiên như vậy cũng dạy `train/data/build_data.py` đọc thư mục đó
(các dòng training và validation vào pool cùng nhóm của chúng, hold-out thành
một phần chia riêng), với cùng cơ chế chống rò rỉ như mọi dòng khác; trước khi
có pull request đó, không dòng cộng đồng nào tới được một model.

## Bản sửa được phát hành ra sao

1. **Một luật hoặc một model.** Một mẫu hẹp, độ chính xác cao trở thành một
   luật L1; những gì rộng hơn phải chờ một classifier được train với các dòng
   mới. Luật được phát triển trên các báo cáo và trên các phần validation của
   `train/data`, không bao giờ trên `eval/`, và pull request ghi rõ đã dùng dữ
   liệu nào.
2. **Đo trên hold-out.** Một ứng viên được chấm điểm một lần trên hold-out cộng
   đồng và các phần hold-out khác, sau cùng mới đến `eval/`, với các con số
   ghi trong pull request.
3. **Shadow mode.** Một classifier mới chạy song song với classifier đang dùng
   (`SHADOW_L2_MODEL`, README
   [Shadow mode and model reload](../README.md#shadow-mode-and-model-reload)):
   người vận hành thấy trên trang **Models** những chỗ nó sẽ chặn hoặc cho qua
   khác đi trên chính lưu lượng của họ, mà không thay đổi quyết định nào.
4. **Mặc định.** Sau một release có ứng viên chạy ở shadow mode mà không có
   regression nào được báo, model manifest sẽ khuyến nghị nó và một release
   sau đó đặt nó làm mặc định. CHANGELOG nêu tên các báo cáo mà nó sửa.

Người báo có thể kiểm tra bản sửa bằng release có nêu issue của họ, hoặc sớm
hơn bằng `POST /guardrail/scan` trên một gateway đang chạy ứng viên.

## Ghi công

- Mục CHANGELOG của release chứa bản sửa cảm ơn người báo bằng tên GitHub và
  số issue của họ.
- `train/DATA_CARD.md` liệt kê những người báo có văn bản nằm trong dữ liệu
  (`import_report.json` có danh sách cho mỗi lần import).
- Báo cáo riêng được ghi công trong security advisory, như SECURITY.md mô tả.

Hãy nói trong issue nếu bạn không muốn được nêu tên.

<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Ví dụ

> English: [README.md](README.md). Nếu hai bản khác nhau, bản tiếng Anh là bản chính.

Các ví dụ chạy được của những ứng dụng gửi lời gọi model qua gateway Guard
Spec. Mỗi ví dụ minh họa một request được cho qua, một request streaming và
một request bị gateway chặn, và thoát với mã 1 khi gateway không làm đúng như
ví dụ mong đợi.

| Ví dụ | Minh họa |
|---|---|
| [python/openai-sdk](python/openai-sdk/) | OpenAI Python SDK: chat, streaming, bắt lỗi chặn HTTP 400 `content_filter` |
| [python/langchain](python/langchain/) | LangChain `ChatOpenAI` (`langchain-openai`) trỏ vào gateway |
| [python/llamaindex](python/llamaindex/) | LlamaIndex `OpenAILike` trỏ vào gateway |
| [python/rag](python/rag/) | Một pipeline RAG có tài liệu bị đầu độc: bị chặn (`INDIRECT_ACTION=block`), bị che (`redact`), hoặc bị loại ngay khi nạp bằng `POST /guardrail/scan` |
| [typescript/openai-sdk](typescript/openai-sdk/) | OpenAI TypeScript SDK: chat, streaming, xử lý lỗi |
| [typescript/vercel-ai-sdk](typescript/vercel-ai-sdk/) | Vercel AI SDK (`@ai-sdk/openai` với `baseURL`): `generateText`, `streamText`, xử lý lỗi |
| [n8n](n8n/) | Một workflow n8n có thể import: node HTTP Request và node OpenAI Chat Model trỏ vào gateway |
| [custom-backend](custom-backend/) | Gateway đứng trước API JSON của chính tổ chức (`/v1/backend/{upstream}/{path}`): yêu cầu sạch được chuyển tiếp nguyên từng byte, yêu cầu chứa injection không bao giờ tới backend, e-mail trong phản hồi bị che, đường dẫn ngoài phạm vi bị từ chối |

Các dependency đều được ghim phiên bản: `pyproject.toml` và `uv.lock` cho
Python (chạy bằng [uv](https://docs.astral.sh/uv/)), `package.json` và
`package-lock.json` cho TypeScript (Node.js 22 trở lên).

## Cấu hình

Mọi ví dụ đều đọc cùng các biến sau:

| Biến | Ví dụ | |
|---|---|---|
| `GUARDSPEC_BASE_URL` | `http://localhost:8080` | Gateway, không kèm `/v1` (nếu có `/v1` ở cuối thì vẫn được chấp nhận và bị bỏ đi) |
| `GUARDSPEC_API_KEY` | `gs_...` | Một key Guard Spec: lấy từ giao diện quản trị (API keys) hoặc `POST /v1/organizations/{id}/api-keys`. Không bao giờ dùng key của nhà cung cấp model |
| `MODEL` | `llama3.2` | Một model mà upstream của bạn (`UPSTREAM_LLM_URL`) phục vụ; gateway chuyển nguyên tên này đi |

Thư mục này không chứa key nào. Hãy đặt key của bạn trong biến môi trường:

```bash
export GUARDSPEC_BASE_URL=http://localhost:8080
export GUARDSPEC_API_KEY=gs_...        # your key
export MODEL=llama3.2
cd examples/python/openai-sdk && uv run --frozen main.py
```

## Chạy với gateway của bạn

Khởi động Guard Spec theo [hướng dẫn bắt đầu nhanh](../README.vi.md#bắt-đầu-nhanh)
và trỏ `UPSTREAM_LLM_URL` vào một model (Ollama, OpenAI, vLLM...); tạo key
trong giao diện quản trị. Bước truy vấn của ví dụ RAG phụ thuộc vào
`INDIRECT_ACTION` của gateway (mặc định `block`; `redact` cho thấy nhánh còn
lại).

Khi không có upstream, gateway trả lời các request được cho qua bằng một
thông điệp cố định (`[guardrail passed — configure UPSTREAM_LLM_URL ...]`)
dạng JSON thường, kể cả khi client yêu cầu stream; các ví dụ streaming cần một
upstream, thật hoặc bản giả bên dưới.

## Gateway dùng tạm để thử (và cho CI)

[`dev/start.sh`](dev/start.sh) khởi động mọi thứ các ví dụ cần từ bản checkout
này, không có giao diện quản trị và không tải model:

- Postgres kèm các migration (`docker compose`, project `gs-examples`,
  thông tin đăng nhập cho môi trường phát triển, port 55432);
- [`dev/fake_upstream.py`](dev/fake_upstream.py), một model giả tương thích
  OpenAI (chỉ dùng thư viện chuẩn), trả lời bằng cách lặp lại những gì nó nhận
  được, để bạn thấy những gì đã đến được model qua gateway;
- gateway build bằng `go build ./cmd/gateway`, chỉ có lớp luật
  (`DETECTOR_LAYERS=l1`), chạy hai bản: `INDIRECT_ACTION=block` ở port 18180
  và `INDIRECT_ACTION=redact` ở port 18181;
- một key ngẫu nhiên cho lần chạy này, ghi cùng các URL vào `dev/.state/env`.

```bash
examples/dev/start.sh            # needs docker compose v2, Go, python3
examples/dev/run-all.sh          # every example; needs uv and Node.js 22
examples/dev/stop.sh             # stops it and deletes the database volume
```

Để chạy tay một ví dụ, nạp các biến trước:
`set -a; . examples/dev/.state/env; set +a`. Đặt `UPSTREAM_LLM_URL` trước khi
chạy `start.sh` thì sẽ dùng model thật thay cho model giả. Chỉ dành cho môi
trường phát triển: mật khẩu database là mật khẩu ai cũng biết trong
`docker-compose.override.yml`.

[Workflow Examples](../.github/workflows/examples.yml) chạy `start.sh` và
`run-all.sh` trên các pull request có chạm vào ví dụ hoặc gateway. Đây không
phải check bắt buộc.

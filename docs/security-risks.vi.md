# Rủi ro bảo mật và gia cố

> English: [security-risks.md](security-risks.md).

Trang này dành cho người triển khai và vận hành Guard Spec. Nó liệt kê những
rủi ro vẫn còn khi Guard Spec đứng trước LLM của bạn và cách giảm từng rủi ro.
Để biết gateway bảo vệ được gì và không bảo vệ được gì, hãy đọc
[Mô hình bảo mật và giới hạn](../README.vi.md#mô-hình-bảo-mật-và-giới-hạn) trước. Báo lỗ hổng theo
[SECURITY.md](../SECURITY.md).

Guard Spec là một lớp phòng thủ. Nó giảm khả năng chỉ dẫn bị chèn đến được
model và hạn chế những gì câu trả lời có thể làm lộ. Riêng nó không làm một ứng
dụng LLM trở nên an toàn.

## Mục lục

- [Tóm tắt](#tóm-tắt)
- [Rủi ro phát hiện](#rủi-ro-phát-hiện)
- [Rủi ro ở ứng dụng và agent](#rủi-ro-ở-ứng-dụng-và-agent)
- [Rủi ro triển khai](#rủi-ro-triển-khai)
- [Rủi ro danh tính và quyền truy cập](#rủi-ro-danh-tính-và-quyền-truy-cập)
- [Rủi ro dữ liệu và quyền riêng tư](#rủi-ro-dữ-liệu-và-quyền-riêng-tư)
- [Rủi ro chuỗi cung ứng](#rủi-ro-chuỗi-cung-ứng)
- [Rủi ro vận hành](#rủi-ro-vận-hành)
- [Checklist gia cố](#checklist-gia-cố)

## Tóm tắt

| # | Rủi ro | Hậu quả | Cách giảm |
|---|---|---|---|
| D1 | Không phát hiện được tấn công | Chỉ dẫn bị chèn đến được model | Tool quyền tối thiểu, người xác nhận, output guard, exemplar |
| D2 | Chặn nhầm request vô hại | Người dùng bị từ chối | Đo trên lưu lượng thật, allow exemplar, `DETECTOR_LAYERS` |
| D3 | Lớp model thiếu mà không ai biết | Chỉ chạy L1, tỷ lệ bắt giảm | `DETECTOR_REQUIRE_ML=true`, cảnh báo khi `/readyz` báo `degraded` |
| D4 | Injection gián tiếp trong phần không quét | Kết quả tool hoặc system prompt không được kiểm | `SCAN_ROLES`, `scan_roles` theo org, `SPOTLIGHT` |
| D5 | Lịch sử hội thoại bị giả mạo trên `/v1/messages` và `/v1/responses` | Văn bản chưa quét đặt vào các lượt trước tới được model | Chỉ cấp key cho client tin cậy, hoặc `SCAN_HISTORY=full` |
| D6 | Trạng thái hội thoại lưu ở upstream (`/v1/responses`) | Các lượt trước mà gateway không thấy tới được model | `RESPONSES_SERVER_STATE=refuse` (mặc định); mỗi org một key upstream riêng |
| A1 | Agent dùng tool sai mục đích | Mất dữ liệu, hành động ngoài ý muốn | Phân quyền trong ứng dụng, kiểm soát egress, xác nhận |
| A2 | Rò dữ liệu qua link được giữ lại | Dữ liệu ra ngoài qua câu trả lời | Allowlist host ngắn, tắt tự tạo link trong UI |
| P1 | Dịch vụ chạy không có TLS | Lộ thông tin đăng nhập và prompt trên mạng | TLS ở reverse proxy hoặc load balancer |
| P2 | Control plane hoặc metrics ra Internet | Tấn công đăng nhập admin, lộ thông tin | Mạng riêng, VPN hoặc SSO đứng trước |
| P3 | Upstream của org trỏ vào host nội bộ hoặc nhận key của bạn | SSRF, lộ key | `UPSTREAM_ALLOW_PRIVATE=false`, `UPSTREAM_KEY_ORGS` |
| P4 | Vượt rate limit bằng số lượng lớn | Tốn chi phí, từ chối dịch vụ | WAF hoặc rate limiter phía trước; giới hạn tính theo replica |
| I1 | Secret yếu hoặc bị lộ | Bị chiếm toàn bộ | Secret mạnh trong secret manager, xoay vòng |
| I2 | Mất `MFA_ENC_KEY` | 2FA của mọi người ngừng hoạt động | Sao lưu cùng database |
| I3 | Ai cũng tạo được tổ chức | Admin không tin cậy chọn upstream | Thiết lập ở P3, giới hạn người đăng ký |
| I4 | Đăng ký 2FA tin ở lần đầu | Kẻ có mật khẩu đăng ký trước | Bắt buộc 2FA sớm; reset 2FA khi nghi ngờ |
| I5 | `TRUSTED_PROXIES` sai | Giả mạo IP trong rate limit và log | Chỉ liệt kê proxy của bạn |
| R1 | Lưu nội dung prompt trong audit | Dữ liệu cá nhân lưu trữ lâu dài | Để tắt `AUDIT_STORE_CONTENT`, đặt thời hạn lưu |
| R2 | Dữ liệu cá nhân lọt qua bộ che | Lộ trong câu trả lời | Bộ che dựa trên regex; tự kiểm thêm |
| R3 | Trace ID hoặc nhãn metric lộ dữ liệu tenant | Lộ thông tin giữa các tenant | Mặc định an toàn; xem kỹ trước khi đổi |
| S1 | Image, binary hoặc model bị sửa | Chạy mã tuỳ ý hoặc bộ phát hiện yếu đi | cosign verify, model ghim SHA-256, digest |
| S2 | Lỗ hổng đã biết trong thư viện | Dịch vụ bị khai thác | Cập nhật bản mới nhất; theo dõi advisory |
| O1 | Lạm dụng quyền database hoặc admin | Đổi policy, đọc audit | Quyền tối thiểu, activity log, sao lưu |
| O2 | Fail-closed gây gián đoạn | Request bị từ chối (503) | Health check, nhiều replica, cảnh báo |

## Rủi ro phát hiện

### D1. Không phát hiện được tấn công

Phát hiện mang tính xác suất. Cách diễn đạt mới, ngôn ngữ khác ngoài tiếng Anh
và tiếng Việt, kiểu mã hoá mà L1 chỉ giải được một phần (như base64) và tấn
công nhiều lượt mà từng tin nhắn trông vô hại đều có thể lọt. Với các lớp model
mặc định, bộ eval cho tỷ lệ bắt khoảng 0,93 ở ngưỡng chặn (xem
[Benchmark](../README.vi.md#benchmark)); phần còn lại đến được model.

Nên làm:

- Thiết kế ứng dụng như thể một số injection sẽ đến được model: cấp cho tool
  quyền tối thiểu và để người xác nhận các hành động rủi ro.
- Giữ output guard bật; nó hạn chế những gì một injection thành công có thể làm lộ.
- Thêm các tấn công thấy trong lưu lượng thật làm block exemplar cho tổ chức.
- Báo các cách vượt qua một cách riêng tư ([SECURITY.md](../SECURITY.md)); chúng
  thuộc phạm vi nhận báo cáo.

### D2. Chặn nhầm request vô hại

Với L2 và L3, khoảng 1,4% prompt vô hại trong bộ eval bị chặn; teencode tiếng
Việt vô hại là 3,5%, tiếng Anh là 1,7%. Dữ liệu eval và huấn luyện tiếng Việt là
dữ liệu tổng hợp, nên tỷ lệ của bạn có thể khác.

Nên làm:

- Chạy trước trên bản sao lưu lượng thật và đọc các audit có `block`.
- Thêm allow exemplar cho các trường hợp chặn nhầm.
- Nếu chặn nhầm tốn kém hơn bỏ sót, chạy `DETECTOR_LAYERS=l1` (khoảng 0,1% chặn
  nhầm, tỷ lệ bắt thấp hơn).

### D3. Lớp model thiếu mà không ai biết

Khi thiếu model hoặc model nạp lỗi, gateway ghi cảnh báo và tiếp tục chạy chỉ
với L1. Khi đó `/readyz` báo `"degraded":true`.

Nên làm:

- Đặt `DETECTOR_REQUIRE_ML=true` để gateway từ chối khởi động khi thiếu lớp
  model, hoặc dùng image `gateway-full` có sẵn model.
- Cảnh báo khi `/readyz` báo `degraded` và theo `guardspec_gateway_detector_errors_total`.

### D4. Injection gián tiếp trong phần không quét

Mặc định gateway phân loại tin nhắn người dùng, kết quả tool và mô tả tool MCP
(`SCAN_ROLES=user,tool,tool_descriptions`). System prompt và tham số tool call
của model không được phân loại nếu bạn không thêm vào; ảnh, âm thanh và các
phần không phải văn bản không được kiểm.

Nên làm:

- Nếu system prompt chứa văn bản do người dùng nhập hoặc lấy từ nguồn ngoài,
  thêm `system` vào `SCAN_ROLES` hoặc bật theo tổ chức (`scan_roles`).
- Gửi tài liệu truy xuất qua `/guardrail/scan` với `documents[]` trước khi đưa
  vào prompt.
- Bật `SPOTLIGHT` (`delimit` hoặc `datamark`) để model phân biệt dữ liệu với chỉ dẫn.

### D5. Lịch sử hội thoại bị giả mạo trên `/v1/messages`

Claude Code và các client Messages API gửi lại toàn bộ hội thoại ở mỗi lượt.
Với `SCAN_HISTORY=latest` (mặc định cho `/v1/messages`), gateway chỉ phân
loại lượt cuối (các tin nhắn sau tin nhắn assistant cuối cùng), cùng system
prompt và tool. Kết quả tool và tài liệu ở các lượt trước vẫn được kiểm (từ
cache quét hoặc quét lại), nên nội dung đã bị chặn hay bị thay thế vẫn bị
chặn hay bị thay thế. Văn bản người dùng ở các lượt trước không được phân
loại lại: gateway tin rằng client giữ API key không giả mạo lịch sử.

Nên làm:

- Chỉ cấp key gateway cho client bạn tin ở mức này (Claude Code của chính
  lập trình viên là một ví dụ).
- Đặt `SCAN_HISTORY=full` khi client không đáng tin; phiên dài sẽ chạm giới
  hạn 128 KiB sớm hơn.

Điều này cũng áp dụng cho các input item của `/v1/responses`: các lượt tới
item cuối cùng do model tạo là lịch sử.

### D6. Trạng thái hội thoại lưu ở upstream trên `/v1/responses`

Với `previous_response_id`, `conversation` hoặc `item_reference`, Responses
API thêm các lượt trước mà upstream đã lưu. Gateway không thấy chúng trong
request nên không quét lại được. Chúng chỉ đi qua gateway khi được tạo nếu
mọi lượt đều đi qua; và response id tạo bằng một key upstream dùng chung cho
nhiều org hay ứng dụng có thể bị bất kỳ ai biết id tham chiếu. Mặc định
(`RESPONSES_SERVER_STATE=refuse`) các request này nhận 400.

Nên làm:

- Giữ mặc định và để client gửi toàn bộ hội thoại trong `input` (model
  reasoning giữ trạng thái bằng `include: ["reasoning.encrypted_content"]` và
  `store: false`).
- Nếu đặt `RESPONSES_SERVER_STATE=allow` để tương thích, cấp cho mỗi org một
  key upstream riêng (upstream có tên với `UPSTREAM_KEY_*`) và theo dõi các
  dòng audit có tag `input:server_state=1`.

## Rủi ro ở ứng dụng và agent

### A1. Agent dùng tool sai mục đích

Gateway thấy tham số tool call và kiểm các chuỗi trong đó, nhưng không thực thi
hay cấp quyền cho tool call và không kiểm soát egress. Nếu model bị thuyết phục
gọi tool, tool sẽ chạy.

Nên làm:

- Kiểm quyền mọi tool call trong ứng dụng theo quyền của người dùng cuối, không
  theo yêu cầu của model.
- Hạn chế kết nối ra ngoài từ các dịch vụ chạy tool.
- Yêu cầu xác nhận cho hành động gửi dữ liệu ra ngoài, tiêu tiền hoặc xoá.

### A2. Rò dữ liệu qua link được giữ lại

Output guard gỡ ảnh và link tới host ngoài allowlist, nhưng giữ link tới host
trong allowlist và URL dạng văn bản không có query string. Nếu UI của bạn tự
biến URL thành link, kênh này vẫn có thể bị dùng để làm lộ dữ liệu.

Nên làm:

- Giữ allowlist ngắn; không cho các host mà ai cũng đăng nội dung được.
- Không tự tạo link từ URL trong câu trả lời, không tải ảnh từ xa trong đó.

## Rủi ro triển khai

### P1. Dịch vụ chạy không có TLS

Gateway và control plane phục vụ HTTP thường. API key, cookie phiên và prompt
đi qua mạng dạng rõ nếu không có thành phần nào phía trước kết thúc TLS.

Nên làm:

- Đặt reverse proxy hoặc load balancer có TLS trước cả hai dịch vụ.
- Dùng `sslmode=require` hoặc mạnh hơn trong URL database.
- Đặt `PUBLIC_BASE_URL` là địa chỉ `https://` của control plane.

### P2. Control plane hoặc metrics ra Internet

Control plane chứa admin UI và API quản trị. `/metrics` chạy trên listener riêng
(`METRICS_ADDR`).

Nên làm:

- Chỉ mở gateway cho ứng dụng. Để control plane trong mạng riêng, sau VPN hoặc
  proxy xác thực danh tính.
- Không bao giờ cho cổng metrics đi qua ingress hay load balancer công khai.
- Để trống `ALLOWED_ORIGINS` trừ khi một origin khác thật sự cần gọi API.

### P3. Upstream của org trỏ vào host nội bộ hoặc nhận key của bạn

Admin của một org tự chọn nơi các upstream có tên trỏ tới.

Nên làm:

- Giữ `UPSTREAM_ALLOW_PRIVATE=false` (mặc định) trừ khi mọi admin org đều tin
  cậy được. Địa chỉ metadata của cloud luôn bị từ chối.
- Giữ `UPSTREAM_KEY_ORGS` hẹp: nó quyết định org nào được dùng biến
  `UPSTREAM_KEY_*` nào. File compose đặt cả hai cho một nhóm dùng riêng; hãy
  đổi trước khi cho người không tin cậy tạo tổ chức.

### P4. Vượt rate limit bằng số lượng lớn

Rate limit lưu trong bộ nhớ từng replica gateway, nên giới hạn thực tế tăng
theo số replica, và nó không chặn được một đợt tràn kết nối.

Nên làm: đặt WAF hoặc rate limiter dùng chung trước gateway, và đặt giới hạn chi
tiêu ở nhà cung cấp LLM.

## Rủi ro danh tính và quyền truy cập

### I1. Secret yếu hoặc bị lộ

`POSTGRES_PASSWORD`, `GUARDSPEC_APP_PASSWORD`, `JWT_SECRET`, `MFA_ENC_KEY` và
`ADMIN_PASSWORD` bảo vệ mọi thứ. Ngoài `GUARD_ENV=dev`, các dịch vụ từ chối
secret thiếu, mặc định hoặc quá ngắn, nhưng không biết được secret đã bị lộ hay chưa.

Nên làm:

- Sinh secret ngẫu nhiên (`scripts/quickstart.sh` làm việc này) và giữ trong
  secret manager, không để trong Git hay Helm values.
- Không bao giờ chạy production với `GUARD_ENV=dev`.
- Đổi `JWT_SECRET` (mọi người bị đăng xuất) và mật khẩu database khi nghi bị lộ.
  Thu hồi API key không còn dùng.

### I2. Mất `MFA_ENC_KEY`

Secret TOTP được mã hoá bằng `MFA_ENC_KEY`. Mất key thì 2FA của mọi người không
dùng được, và control plane từ chối khởi động khi đã có người dùng bật 2FA.

Nên làm: sao lưu key cùng với database, nhưng cất ở nơi khác với bản sao lưu database.

### I3. Ai cũng tạo được tổ chức

Người dùng đã đăng nhập nào cũng tạo được tổ chức và trở thành admin của nó.
Xem P3 để biết admin đó cấu hình được những gì.

Nên làm: nếu người không tin cậy truy cập được control plane, dùng SSO với
`allowed_domains` và giữ chặt các thiết lập ở P3.

### I4. Đăng ký 2FA tin ở lần đầu

Khi một tổ chức bắt đầu bắt buộc 2FA, thành viên chưa có 2FA sẽ đăng ký ở lần
đăng nhập tiếp theo chỉ với mật khẩu. Ai đã có mật khẩu đó có thể đăng ký
authenticator của họ trước.

Nên làm: bắt buộc 2FA ngay từ đầu, và reset 2FA của thành viên khi nghi ngờ.

### I5. `TRUSTED_PROXIES` sai

`TRUSTED_PROXIES` quyết định tin `X-Forwarded-For` của ai. Đặt quá rộng thì
client tự chọn được địa chỉ dùng cho rate limit, phiên và activity log; để
trống khi đứng sau proxy thì mọi client trông như một.

Nên làm: liệt kê đúng địa chỉ hoặc CIDR của các proxy của bạn.

## Rủi ro dữ liệu và quyền riêng tư

### R1. Lưu nội dung prompt trong audit

Mặc định audit lưu điểm, quyết định, SHA-256 và độ dài của body, không lưu nội
dung. `AUDIT_STORE_CONTENT=true` hoặc thiết lập `audit_store_content` theo org
sẽ lưu prompt và câu trả lời được đệm.

Nên làm:

- Để tắt lưu nội dung nếu không cần, và báo cho người dùng nếu bật.
- Đặt `AUDIT_RETENTION_DAYS`, mã hoá database khi lưu trữ và hạn chế người đọc được.

### R2. Dữ liệu cá nhân lọt qua bộ che

Output guard che email, số điện thoại, CCCD, số thẻ Việt Nam và địa chỉ IPv4
bằng mẫu regex. Định dạng khác, của nước khác, hay dữ liệu cá nhân viết bằng
chữ đều không bị bắt. Prompt gửi lên upstream không được che.

Nên làm: nếu không được gửi dữ liệu cá nhân cho nhà cung cấp LLM, hãy loại bỏ nó
trong ứng dụng trước khi gửi, hoặc dùng nhà cung cấp và hợp đồng cho phép điều đó.

### R3. Trace ID hoặc nhãn metric lộ dữ liệu tenant

Nhãn metric chỉ nhận giá trị trong tập cố định, nhãn theo tenant tắt
(`METRICS_TENANT_LABELS=false`) và `traceparent` không gửi lên upstream
(`OTEL_PROPAGATE_UPSTREAM=false`). Bật các mục này là chia sẻ nhiều hơn với hệ
thống giám sát hoặc nhà cung cấp.

Nên làm: chỉ đổi các mặc định này khi hệ thống nhận là tin cậy được.

## Rủi ro chuỗi cung ứng

### S1. Image, binary hoặc model bị sửa

Nên làm:

- Kiểm image và archive bằng cosign trước khi triển khai
  ([Verifying releases](../SECURITY.md#verifying-releases)), và triển khai theo
  digest thay vì tag.
- Tải model bằng `models pull`, lệnh này kiểm SHA-256 đã ghim trong
  `models/manifest.yaml`. Với môi trường không có Internet, chỉ mirror các file đã kiểm.

### S2. Lỗ hổng đã biết trong thư viện

Dự án chưa tới 1.0; bản vá bảo mật chỉ có trong bản phát hành kế tiếp.

Nên làm: theo dõi release và security advisory của repo, nâng lên bản `0.x` mới
nhất, và quét các image bạn chạy.

## Rủi ro vận hành

### O1. Lạm dụng quyền database hoặc admin

Ai có quyền database hoặc instance admin đều đổi được policy, đọc audit và tạo API key.

Nên làm: chỉ cấp role ứng dụng (`guardspec_app`) cho các dịch vụ, giữ role owner
cho migration, cấp cho người dùng vai trò thấp nhất đủ dùng, và xem activity log.

### O2. Fail-closed gây gián đoạn

Nếu policy, thiết lập org hoặc bộ phát hiện không chạy được, gateway từ chối
request (503) thay vì cho qua. Vì vậy database gặp sự cố sẽ làm dừng lưu lượng LLM.

Nên làm: chạy nhiều hơn một replica gateway, dùng Postgres có tính sẵn sàng cao,
và cảnh báo theo tỷ lệ 503 và `/readyz`.

## Checklist gia cố

- [ ] TLS trước cả hai dịch vụ; kết nối database với `sslmode=require` hoặc mạnh hơn
- [ ] Ứng dụng chỉ truy cập được gateway; cổng control plane và metrics ở mạng riêng
- [ ] `GUARD_ENV` không phải `dev`; mọi secret ngẫu nhiên và nằm trong secret manager
- [ ] `MFA_ENC_KEY` được sao lưu tách khỏi bản sao lưu database
- [ ] `DETECTOR_REQUIRE_ML=true` hoặc image `gateway-full`; có cảnh báo khi `degraded`
- [ ] `UPSTREAM_ALLOW_PRIVATE=false` và `UPSTREAM_KEY_ORGS` hẹp
- [ ] `TRUSTED_PROXIES` liệt kê đúng các proxy
- [ ] `SCAN_ROLES` bao mọi chỗ văn bản không tin cậy đi vào prompt
- [ ] Allowlist link ngắn; UI không tự tạo link từ câu trả lời của model
- [ ] Tắt lưu nội dung; đã đặt `AUDIT_RETENTION_DAYS`
- [ ] SSO hoặc bắt buộc 2FA cho mọi người có quyền admin
- [ ] WAF hoặc rate limiter dùng chung trước gateway; giới hạn chi tiêu ở nhà cung cấp
- [ ] Image và archive đã kiểm bằng cosign; triển khai theo digest
- [ ] Tool được kiểm quyền trong ứng dụng; hành động rủi ro có người xác nhận

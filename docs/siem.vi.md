<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Xuất sự kiện sang SIEM

> English: [siem.md](siem.md).

Guard Spec gửi các sự kiện của một tổ chức tới SIEM của bạn dưới dạng bản ghi
[OCSF 1.9.0](https://schema.ocsf.io/1.9.0/): phát hiện prompt injection, đăng
nhập thất bại, đổi vai trò và 2FA, đổi policy và upstream, cùng mọi thao tác
quản trị khác. Bản ghi chỉ chứa metadata (id, loại, điểm, quyết định, địa chỉ
đã hash), không bao giờ có prompt, câu trả lời hay secret.

| Đích | Cách gửi | Secret |
|---|---|---|
| Splunk | HTTP Event Collector (`/services/collector/event`) | HEC token |
| Elasticsearch / OpenSearch | `_bulk`, mỗi bản ghi một `create`, `_id` = `metadata.uid` của bản ghi | API key (`base64(id:key)`) |
| Microsoft Sentinel | Azure Monitor Logs Ingestion API (data collection rule) | Client secret của Entra ID |
| Syslog qua TLS | Thông điệp RFC 5424, khung octet-counting (RFC 6587), TLS (RFC 5425); CEF hoặc OCSF JSON | không (TLS) |
| HTTP | `POST` một mảng JSON các bản ghi | bearer token tuỳ chọn |

## Cài đặt

1. Người vận hành đặt secret vào một biến `SIEM_*` của control plane (hoặc file
   / tham chiếu Vault, [secret](security/README.vi.md#secret-lấy-từ-đâu)) và cho
   phép tổ chức dùng nó trong `ALERTS_SECRET_ORGS`: `SIEM_SPLUNK_TOKEN=siem:<org-id>`
   (hoặc `siem:*`). SIEM trong mạng nội bộ cần thêm tổ chức trong
   `ALERTS_PRIVATE_ORGS`.
2. Admin thêm đích ở **Cảnh báo → Xuất sang SIEM**: loại đích, cấu hình, tên
   biến, tuỳ chọn loại sự kiện (`detection.`, `security.login_failed`, ...) và
   mức độ thấp nhất. **Gửi thử** gửi một bản ghi `alert.test`.
3. Đích bắt đầu với các sự kiện xảy ra sau khi được thêm.

API: `GET|POST /v1/organizations/{org}/siem-sinks`,
`PUT|DELETE .../siem-sinks/{id}`, `POST .../siem-sinks/{id}/test` (admin).

## Cách gửi

- Control plane kiểm tra các đích mỗi `SIEM_EXPORT_INTERVAL` (mặc định `5s`),
  gửi tối đa 200 sự kiện một lần cho mỗi đích, khoảng 10 giây sau khi sự kiện
  xảy ra (để không bỏ sót batch commit muộn).
- **Ít nhất một lần.** Batch lỗi được gửi lại; SIEM có thể bỏ trùng theo
  `metadata.uid` (Elasticsearch tự làm: đó là id của tài liệu).
- Đích bị lỗi chờ 10 giây, nhân đôi tới tối đa 30 phút, rồi gửi bù từ chỗ đã
  dừng. Trang quản trị hiện lỗi và số lần. Sự kiện được giữ 30 ngày; đích ngừng
  lâu hơn sẽ mất các sự kiện cũ nhất.
- Nhiều bản control plane chia việc: mỗi đích chỉ được giao cho một bản tại một
  thời điểm.
- URL được kiểm tra như webhook cảnh báo: chỉ https, không địa chỉ link-local
  hay metadata, không địa chỉ nội bộ nếu không có `ALERTS_PRIVATE_ORGS` và
  `allow_private`.

## Bản ghi

Ánh xạ sự kiện sang class OCSF (Detection Finding 2004, Authentication 3002,
Account Change 3001, API Activity 6003), các truy vấn mẫu cho Splunk, Kibana,
Sentinel (KQL), bảng tuỳ chỉnh của Sentinel và định dạng CEF có ở
[bản tiếng Anh](siem.md#records).

## Đã kiểm tra

Bản ghi được đối chiếu với các thuộc tính bắt buộc và giá trị hợp lệ của class
và object OCSF 1.9.0 chính thức (`internal/siem/testdata/ocsf-1.9.0-required.json`).
Việc gửi được thử với server giả của Splunk HEC, Elasticsearch, Logs Ingestion
API và syslog TLS, và với Elasticsearch 8.17 thật (`SIEM_LIVE_ELASTIC_URL`, test
`TestLiveElasticsearch`).

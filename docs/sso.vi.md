<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SSO bằng SAML và cấp phát tài khoản bằng SCIM

> English: [sso.md](sso.md).

Hướng dẫn này thiết lập đăng nhập một lần (SSO) bằng SAML 2.0 và cấp phát
tài khoản bằng SCIM 2.0 cho Okta, Microsoft Entra ID, Google Workspace và
Keycloak. Tài liệu tham chiếu (mọi trường, mọi bước kiểm tra và endpoint) nằm
ở README tiếng Anh, mục
[Identity, SSO and two-factor authentication](../README.md#identity-sso-and-two-factor-authentication).
Nhà cung cấp OpenID Connect cũng được thiết lập như mô tả ở đó.

Ai làm gì:

| Bước | Ai | Ở đâu |
|---|---|---|
| Thêm nhà cung cấp SAML (dùng chung cả instance) | quản trị viên instance | `/v1/admin/identity-providers`, hoặc trang Identity providers → Add SAML provider |
| Giới hạn cách đăng nhập, nhận tên miền (`domain_join`), `scim_revoke_keys` | owner của tổ chức | `PUT /v1/organizations/:orgId/security`, hoặc trang Security của tổ chức |
| Token SCIM | owner (admin xem được danh sách) | `/v1/organizations/:orgId/scim/tokens`, hoặc trang Security của tổ chức → SCIM |
| Ánh xạ nhóm sang role | owner (admin xem được) | `/v1/organizations/:orgId/group-roles` |

## Mục lục

- [Trước khi bắt đầu](#trước-khi-bắt-đầu)
- [1. Thêm nhà cung cấp SAML](#1-thêm-nhà-cung-cấp-saml)
- [2. Cấu hình identity provider](#2-cấu-hình-identity-provider)
  - [Okta](#okta)
  - [Microsoft Entra ID](#microsoft-entra-id)
  - [Google Workspace](#google-workspace)
  - [Keycloak](#keycloak)
- [3. Thiết lập của tổ chức](#3-thiết-lập-của-tổ-chức)
- [4. Cấp phát bằng SCIM](#4-cấp-phát-bằng-scim)
  - [Cấp phát với Okta](#cấp-phát-với-okta)
  - [Cấp phát với Entra ID](#cấp-phát-với-entra-id)
  - [Đăng nhập cho người dùng do SCIM tạo](#đăng-nhập-cho-người-dùng-do-scim-tạo)
- [5. Role theo nhóm](#5-role-theo-nhóm)
- [Xử lý sự cố](#xử-lý-sự-cố)
- [Lưu ý bảo mật](#lưu-ý-bảo-mật)

## Trước khi bắt đầu

- Đặt `PUBLIC_BASE_URL` của control plane là địa chỉ `https://` bên ngoài, ví
  dụ `https://guard.example.com`. Mọi URL cấu hình ở identity provider đều suy
  ra từ biến này; không có nó thì SAML không dùng được, và đổi nó về sau nghĩa
  là phải sửa lại cấu hình ở identity provider.
- Trình duyệt phải vào control plane đúng địa chỉ đó: cookie đăng nhập được
  đặt cho địa chỉ này.
- Đồng hồ: khoảng hiệu lực của assertion được kiểm tra với độ lệch 2 phút, chỉ
  cho `NotBefore`. Hãy chạy NTP trên máy chủ control plane.

## 1. Thêm nhà cung cấp SAML

Tải **metadata XML** của identity provider (mỗi mục bên dưới nói lấy ở đâu).
Metadata phải có một `SingleSignOnService` với binding HTTP-Redirect và một
chứng chỉ ký; Guard Spec gửi AuthnRequest theo binding đó, và đọc chứng chỉ
cùng entity id từ metadata.

```bash
CP=https://guard.example.com/v1
AUTH="Authorization: Bearer $ADMIN_TOKEN"   # quản trị viên instance
jq -n --rawfile md idp-metadata.xml '{
  type: "saml", display_name: "Okta", saml_metadata: $md,
  allowed_domains: ["example.com"], auto_provision: true,
  trust_email_for_linking: false, saml_groups_attribute: "groups"
}' | curl -s $CP/admin/identity-providers -H "$AUTH" -H 'Content-Type: application/json' -d @- | jq '{id, saml_sp}'
# {"id": "6f1c…", "saml_sp": {"entity_id": "https://guard.example.com/v1/auth/saml/6f1c…/metadata",
#   "acs_url": "https://guard.example.com/v1/auth/saml/6f1c…/acs", "metadata_url": "https://guard.example.com/v1/auth/saml/6f1c…/metadata"}}
```

Identity provider cần id của nhà cung cấp trước, nên thứ tự thường là: tạo
app SAML ở IdP với URL tạm, tải metadata của nó, thêm nhà cung cấp ở Guard
Spec, rồi điền `entity_id` và `acs_url` thật vào app ở IdP. Một số IdP nhập
được thẳng `<PUBLIC_BASE_URL>/v1/auth/saml/<id>/metadata`.

| Giá trị | Điền vào đâu ở identity provider |
|---|---|
| `entity_id` | Audience, SP entity id, Identifier, Client ID (Keycloak) |
| `acs_url` | Single sign-on URL, Reply URL, ACS URL, Recipient và Destination |
| NameID | Một giá trị ổn định, duy nhất cho mỗi người; identity được so khớp theo nó. Chọn định dạng persistent nếu được (AuthnRequest của Guard Spec yêu cầu định dạng này) |
| email | Attribute tên `email` (hoặc một tên thông dụng, hoặc đặt `saml_email_attribute`); khi không có attribute, NameID được dùng nếu nó là email |
| tên hiển thị | Tuỳ chọn: `displayName` (hoặc `saml_name_attribute`) |
| nhóm | Tuỳ chọn, cho [role theo nhóm](#5-role-theo-nhóm): `groups` (hoặc `saml_groups_attribute`) |

Guard Spec không ký AuthnRequest và không nhận assertion mã hoá: hãy tắt "yêu
cầu request có ký" và mã hoá assertion ở identity provider. Response hoặc
assertion phải được ký.

`auto_provision` tạo tài khoản ở lần đăng nhập đầu cho email mới thuộc
`allowed_domains`; `trust_email_for_linking` cho phép một lần đăng nhập nhận
một tài khoản đã có nhưng chưa có mật khẩu và chưa có identity nào, đúng là
trường hợp của tài khoản do SCIM tạo ([bên dưới](#đăng-nhập-cho-người-dùng-do-scim-tạo)).

## 2. Cấu hình identity provider

### Okta

1. **Applications → Create App Integration → SAML 2.0**.
2. General settings: đặt tên; rồi **Configure SAML**:
   - Single sign-on URL: `acs_url`; giữ ô **Use this for Recipient URL and
     Destination URL**.
   - Audience URI (SP Entity ID): `entity_id`.
   - Name ID format: Persistent; Application username: Okta username hoặc
     Email.
   - Attribute Statements: `email` → `user.email`; `displayName` →
     `user.displayName` (hoặc `user.firstName + " " + user.lastName`).
   - Group Attribute Statements (cho role): tên `groups`, bộ lọc **Matches
     regex** `.*`, hoặc **Starts with** một tiền tố như `guardspec-` để chỉ
     gửi các nhóm có ánh xạ.
3. Hoàn tất, rồi ở **Sign On** mở metadata URL (hoặc **View SAML setup
   instructions** → IDP metadata) và lưu XML. Metadata của Okta có binding
   HTTP-Redirect.
4. **Assignments**: gán người hoặc nhóm được đăng nhập.

### Microsoft Entra ID

1. **Enterprise applications → New application → Create your own
   application** → "Integrate any other application you don't find in the
   gallery (Non-gallery)".
2. **Single sign-on → SAML → Basic SAML Configuration**:
   - Identifier (Entity ID): `entity_id`.
   - Reply URL (Assertion Consumer Service URL): `acs_url`.
   - Để trống Sign on URL, Relay State và Logout URL.
3. **Attributes & Claims**: các claim mặc định đã có
   `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   (`user.mail`) và `.../claims/name`, Guard Spec đọc được. Bảo đảm mọi người
   dùng đều có `user.mail`, hoặc đổi nguồn của claim sang
   `user.userprincipalname` khi UPN chính là email.
4. Nhóm (cho role): **Add a group claim** → "Groups assigned to the
   application"; source attribute **Group ID**. Tên claim
   `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` là một
   tên Guard Spec đọc mặc định. Entra gửi object id của nhóm, nên `group_key`
   của ánh xạ là object id. Khi người dùng ở trong hơn 150 nhóm, Entra gửi một
   đường link thay cho danh sách nhóm và Guard Spec không đi theo link đó:
   chọn "Groups assigned to the application" để danh sách ngắn.
5. **SAML Certificates → Federation Metadata XML**: tải về. Cách ký mặc định
   (ký assertion) được chấp nhận.
6. **Users and groups**: gán người được đăng nhập.

### Google Workspace

1. Admin console → **Apps → Web and mobile apps → Add app → Add custom SAML
   app**.
2. Google Identity Provider details: **Download metadata** (cách 1).
3. Service provider details:
   - ACS URL: `acs_url`.
   - Entity ID: `entity_id`.
   - **Signed response** bật hay tắt đều được (assertion luôn được ký).
   - Name ID format: PERSISTENT; Name ID: Basic Information → Primary email.
4. Attribute mapping: Primary email → `email`. Google không có trường họ tên
   đầy đủ; ánh xạ First name sang `displayName` hoặc bỏ qua tên (tài khoản khi
   đó không có tên hiển thị cho tới khi có người đặt).
5. Nhóm (cho role): **Group membership** → chọn các nhóm, app attribute
   `groups`. Google gửi tên các nhóm đã chọn mà người dùng thuộc về; dùng các
   tên đó làm `group_key`.
6. **User access**: bật app cho các organizational unit hoặc nhóm được đăng
   nhập.

Google Workspace không cấp phát qua SCIM cho custom SAML app: hãy tạo người
dùng bằng `auto_provision` và `domain_join`, hoặc bằng lời mời.

### Keycloak

1. Trong realm: **Clients → Create client**, client type **SAML**, Client ID
   = `entity_id`.
2. Settings:
   - Valid redirect URIs: `acs_url`.
   - Name ID format: `persistent` (hoặc `email`); tắt **Force name ID format**.
   - Bật **Sign documents** (hoặc bật Sign assertions).
3. **Keys**: tắt **Client signature required** (AuthnRequest của Guard Spec
   không ký); tắt **Encrypt assertions**.
4. **Advanced → Assertion Consumer Service POST Binding URL**: `acs_url`.
5. **Client scopes → <client>-dedicated → Add mapper → By configuration**:
   - User Property `email`, SAML Attribute Name `email`.
   - Tuỳ chọn: User Property `firstName` (hoặc một User Attribute), SAML
     Attribute Name `displayName`.
   - Nhóm (cho role): Group list, Group attribute name `groups`, bật
     **Single Group Attribute**, tắt **Full group path**.
6. Metadata: `https://<keycloak>/realms/<realm>/protocol/saml/descriptor`.

Keycloak không có sẵn SCIM client; một plugin SCIM có thể đẩy dữ liệu tới
endpoint SCIM của Guard Spec như bên dưới.

Một bộ Keycloak để thử toàn bộ luồng (`make sso-e2e`) đang được bổ sung; xem
Makefile khi đã có.

## 3. Thiết lập của tổ chức

Owner của tổ chức, ở trang Security của tổ chức hoặc bằng
`PUT /v1/organizations/:orgId/security`:

- `allowed_login_methods`: thêm `saml:<provider id>`, và bỏ `password` nếu
  muốn chỉ đăng nhập bằng SSO (giữ một cách vào cho chính mình tới khi SSO
  chạy; request bị từ chối nếu nó khoá chính bạn ra ngoài).
- `sso_satisfies_mfa`: phiên SAML được tính là SSO.
- `domain_join`: `{"domain":"example.com","provider_id":"<SAML provider id>","role":"member"}`
  thêm người dùng SSO mới của tên miền vào tổ chức. Tên miền phải nằm trong
  `allowed_domains` của nhà cung cấp. Tên miền đã nhận cũng cho SCIM liên kết
  tài khoản sẵn có của tên miền đó và vô hiệu hoá chúng khi deactivate (xem
  bên dưới).
- `scim_revoke_keys` (mặc định bật): thu hồi API key người dùng đã tạo khi
  SCIM deactivate họ.

## 4. Cấp phát bằng SCIM

1. Owner tạo token, ở trang Security của tổ chức → SCIM, hoặc:

   ```bash
   curl -s $CP/organizations/$ORG/scim/tokens -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"name":"Okta","expires_at":"2027-11-01T00:00:00Z"}' | jq -r .token
   # gss_…   (chỉ hiện một lần; Guard Spec chỉ giữ SHA-256 của nó)
   ```

2. Identity provider nhận base URL `<PUBLIC_BASE_URL>/v1/scim/v2` và token
   dưới dạng bearer token. Base URL giống nhau cho mọi tổ chức; token cho biết
   là tổ chức nào.
3. Xoay vòng: tạo token thứ hai, chuyển identity provider sang token mới, rồi
   thu hồi token cũ (`DELETE .../scim/tokens/:id`). Tối đa 20 token còn hiệu
   lực.

Thao tác ở identity provider làm gì ở Guard Spec:

| Thao tác ở IdP | Guard Spec |
|---|---|
| Gán một người | `POST /Users`: tài khoản mới không có mật khẩu, hoặc liên kết với tài khoản sẵn có đã là thành viên hay thuộc tên miền tổ chức đã nhận; vào với role `member` |
| Cập nhật một người | Email (chỉ với tài khoản do SCIM tạo), tên hiển thị, external id |
| Bỏ gán hoặc tạm ngưng | `active: false`: gỡ membership (giữ lại role), thu hồi API key người đó tạo (`scim_revoke_keys`), và với tài khoản thuộc tổ chức thì thu hồi phiên và vô hiệu hoá tài khoản nếu nó không ở tổ chức nào khác |
| Gán lại | `active: true`: trả lại membership với role theo nhóm hoặc role trước đó |
| Xoá | `DELETE /Users/:id`: deactivate, rồi xoá bản ghi SCIM; tài khoản không bị xoá |
| Đẩy nhóm | Nhóm và thành viên, cho [role theo nhóm](#5-role-theo-nhóm) |

### Cấp phát với Okta

1. Trong app SAML: **General → App Settings → Edit → Provisioning: SCIM**,
   lưu.
2. **Provisioning → Integration → Edit**:
   - SCIM connector base URL: `<PUBLIC_BASE_URL>/v1/scim/v2`.
   - Unique identifier field for users: `userName`.
   - Supported provisioning actions: Push New Users, Push Profile Updates,
     Push Groups.
   - Authentication Mode: **HTTP Header**; Authorization: token `gss_…`.
   - **Test Connector Configuration**, lưu.
3. **Provisioning → To App → Edit**: bật Create Users, Update User
   Attributes, Deactivate Users.
4. **Push Groups**: đẩy các nhóm có ánh xạ role (theo tên).

Okta deactivate chứ không xoá người dùng (`PATCH` với `active: false`), gửi
PATCH không có path khi đổi hồ sơ, và gỡ thành viên nhóm bằng
`members[value eq "<id>"]`; Guard Spec nhận được tất cả các dạng này.

### Cấp phát với Entra ID

1. Trong enterprise app: **Provisioning → Get started** (hoặc New
   configuration), Provisioning Mode **Automatic**.
2. Admin Credentials: Tenant URL `<PUBLIC_BASE_URL>/v1/scim/v2`, Secret Token
   là token `gss_…`; **Test Connection**.
3. **Mappings → Provision Microsoft Entra ID Users**: `userName` phải là
   email (mặc định `userPrincipalName` khi UPN là email; nếu không thì ánh xạ
   `mail`). Ánh xạ `active` mặc định
   (`Switch([IsSoftDeleted], , "False", "True", "True", "False")`) là thứ làm
   deactivate. Các attribute mặc định khác được nhận và bỏ qua.
4. **Mappings → Provision Microsoft Entra ID Groups**: giữ `displayName`,
   `externalId` và `members`. Kiểm tra attribute nguồn của `externalId`: khi
   đó là `objectId`, `group_key` của ánh xạ SCIM có thể chính là object id mà
   claim nhóm của SAML gửi.
5. Settings: Scope **Sync only assigned users and groups**; đặt Provisioning
   Status **On**. Dùng **Provision on demand** để thử với một người.

Entra ID gửi `active` dạng chuỗi `"True"` / `"False"`, op PATCH viết hoa
(`Replace`, `Add`, `Remove`) và danh sách thành viên trong giá trị PATCH;
Guard Spec nhận được tất cả các dạng này. Người dùng bị soft-delete được
deactivate; Entra xoá hẳn họ (`DELETE /Users/:id`) sau đó.

### Đăng nhập cho người dùng do SCIM tạo

Tài khoản do SCIM tạo chưa có mật khẩu và chưa có identity SSO. Lần đăng
nhập SSO đầu tiên chỉ liên kết identity theo email khi nhà cung cấp bật
`trust_email_for_linking`; nếu không, đăng nhập bị từ chối với
`account_exists`. Vì vậy, với nhà cung cấp người dùng đăng nhập qua:

- bật `trust_email_for_linking`, và
- đặt `allowed_domains` là các tên miền của bạn, để chỉ email do IdP của bạn
  quản lý mới liên kết được.

Tài khoản sẵn có mà SCIM liên kết (đã là thành viên, hoặc thuộc tên miền đã
nhận) giữ nguyên mật khẩu và email. Nếu tài khoản có mật khẩu, đăng nhập SAML
cùng email bị từ chối với `account_exists`: người dùng đăng nhập bằng mật
khẩu một lần rồi liên kết nhà cung cấp ở **Tài khoản của tôi** (như với
OIDC). Từ đó, SAML đăng nhập vào đúng tài khoản này.

## 5. Role theo nhóm

`PUT /v1/organizations/:orgId/group-roles` (owner) thay toàn bộ ánh xạ của
tổ chức:

```bash
curl -s -X PUT $CP/organizations/$ORG/group-roles -H "$AUTH" -H 'Content-Type: application/json' -d '{"items":[
  {"provider_id": null,           "group_key": "guardspec-admins",  "role": "admin"},
  {"provider_id": null,           "group_key": "guardspec-viewers", "role": "viewer"},
  {"provider_id": "<SAML id>",    "group_key": "guardspec-admins",  "role": "admin"}
]}'
```

- `provider_id` null: nhóm SCIM của tổ chức này, so khớp theo display name
  hoặc external id.
- `provider_id` là một nhà cung cấp SAML: giá trị của attribute nhóm của nó
  (tên nhóm với Okta, Google và Keycloak; object id với Entra ID).
- `role`: `viewer`, `member` hoặc `admin`. Role owner không bao giờ được cấp
  hay thay đổi qua nhóm. So khớp không phân biệt hoa thường; role cao nhất
  khớp được sẽ thắng.

Khi tổ chức đã có ánh xạ nhóm, identity provider quyết định role:

- SCIM: role của người dùng SCIM đang active là role cao nhất mà các nhóm của
  họ được ánh xạ, hoặc `member` khi không nhóm nào khớp; role đổi ngay khi
  thành viên nhóm, tên nhóm hoặc ánh xạ thay đổi.
- SAML: ở mỗi lần đăng nhập qua nhà cung cấp, trong mỗi tổ chức người dùng đã
  là thành viên và có ánh xạ ít nhất một nhóm của nhà cung cấp đó, role trở
  thành role cao nhất khớp với assertion, hoặc `member` khi không nhóm nào
  khớp hoặc assertion không có nhóm. Đăng nhập không bao giờ thêm membership:
  membership đến từ lời mời, `domain_join` hoặc SCIM.
- Tổ chức không có ánh xạ (cho SCIM, hoặc cho nhà cung cấp SAML đó) giữ
  nguyên role đặt tay.

Role đặt tay trong tổ chức có ánh xạ sẽ bị ghi đè ở lần đồng bộ hoặc đăng
nhập kế tiếp, kể cả khi bị hạ xuống.

## Xử lý sự cố

Đăng nhập SAML bị từ chối sẽ về `/ui/#/auth/callback?error=<code>`. Control
plane ghi lý do vào log (`saml login refused`, với `provider`, `code` và
`reason`), và nhật ký hoạt động của instance có `login.failed` kèm mã lỗi.

| Mã | Ý nghĩa | Kiểm tra gì |
|---|---|---|
| `sso_unavailable` | Nhà cung cấp bị tắt, đã xoá hoặc không phải SAML, chưa đặt `PUBLIC_BASE_URL`, hoặc không đọc được metadata | `enabled` của nhà cung cấp; `PUBLIC_BASE_URL`; dán lại metadata. `GET .../start` trả 404 cho nhà cung cấp không tồn tại hoặc đã tắt, và 503 `sso_unavailable` cho nhà cung cấp cấu hình sai |
| `invalid_response` | Chữ ký, issuer, `Destination`, `Recipient`, audience, status, số assertion, thiếu `AudienceRestriction`, thời gian hiệu lực không đọc được, `SubjectConfirmationData` hết hạn, hoặc NameID rỗng hay quá dài | Chứng chỉ ký của IdP có trong metadata (dán lại sau khi IdP đổi chứng chỉ); entity id và ACS URL ở IdP đúng y như `saml_sp` (scheme, host, không có dấu `/` cuối); đã tắt mã hoá assertion; người dùng đã được gán vào app (IdP trả status lỗi cũng rơi vào đây) |
| `expired` | Assertion nằm ngoài khoảng `NotBefore` / `NotOnOrAfter` | Đồng hồ của IdP và control plane |
| `email_not_verified` | Assertion không có email | Attribute email (hoặc `saml_email_attribute`); người dùng có email ở IdP |
| `invalid_state` | `InResponseTo` không khớp request nào đang chờ (quá 10 phút, đã dùng, nhà cung cấp khác), hoặc đăng nhập bắt đầu ở trình duyệt khác (thiếu cookie `gs_saml`) | Bắt đầu lại từ Guard Spec; trình duyệt vào control plane đúng `PUBLIC_BASE_URL`; với http thường, cookie là SameSite=Lax và bị bỏ nếu IdP không cùng site, nên hãy dùng https |
| `idp_initiated_disabled` | Response không có `InResponseTo`: đăng nhập bắt đầu từ dashboard của IdP | Bắt đầu từ trang đăng nhập Guard Spec, hoặc bật `saml_allow_idp_initiated` (xem [lưu ý bảo mật](#lưu-ý-bảo-mật)) |
| `replayed` | Assertion này đã được dùng | Nút back hoặc form bị gửi lại; bắt đầu lại |
| `domain_not_allowed` | Tên miền của email không nằm trong `allowed_domains` | `allowed_domains` của nhà cung cấp |
| `account_exists` | Đã có tài khoản với email này và không liên kết được (có mật khẩu hoặc identity khác, hoặc `trust_email_for_linking` tắt) | [Đăng nhập cho người dùng do SCIM tạo](#đăng-nhập-cho-người-dùng-do-scim-tạo) |
| `account_disabled` | Tài khoản bị vô hiệu hoá (bởi quản trị viên, hoặc bởi SCIM deactivate) | Kích hoạt lại ở IdP (SCIM) hoặc bằng quản trị viên instance |
| `not_provisioned` | Không có tài khoản cho email này và `auto_provision` tắt | Bật `auto_provision`, mời người đó, hoặc cấp phát bằng SCIM |

Sau callback, `POST /v1/auth/oidc/exchange` có thể trả `invalid_code` (mã
dùng một lần sống 60 giây), và tổ chức có thể từ chối phiên với
`login_method_not_allowed` (thêm `saml:<id>` vào `allowed_login_methods`) hoặc
`mfa_required`.

Lỗi SCIM là body lỗi SCIM (`status`, `scimType`, `detail`):

| Status, `scimType` | Ý nghĩa |
|---|---|
| 401 | Thiếu token, token lạ, đã thu hồi hoặc hết hạn (header phải là `Authorization: Bearer gss_…`) |
| 409 `uniqueness` | `userName` hoặc tên nhóm đã có trong tổ chức, tài khoản đã được cấp phát, tài khoản khác đang dùng email mới, hoặc "an account with this email exists outside this organization": hãy mời người đó, hoặc nhận tên miền bằng `domain_join` |
| 409 `mutability` | Deactivate owner duy nhất của tổ chức: thêm owner khác trước |
| 400 `invalidFilter` | Chỉ hỗ trợ `attribute eq "value"` trên các attribute đã liệt kê |
| 400 `invalidValue` | Thiếu hoặc sai `userName` / `displayName`, `active` không phải boolean, thành viên không phải người dùng SCIM của tổ chức, giá trị quá dài |
| 400 `invalidSyntax`, `invalidPath`, `tooMany` | Không phải body SCIM hay PatchOp, path PATCH nhóm không hỗ trợ, quá 1000 thành viên trong một request |
| 429 | Quá 600 request SCIM mỗi phút từ một địa chỉ |

## Lưu ý bảo mật

- **Đăng nhập khởi tạo từ IdP mặc định tắt** (`saml_allow_idp_initiated`).
  Response không có `InResponseTo` không gắn được với trình duyệt nhận nó: ai
  có một response hợp lệ cho tài khoản của chính mình đều có thể gửi nó từ
  một trang mà nạn nhân mở, và đăng nhập nạn nhân vào tài khoản của kẻ tấn
  công (login CSRF), nơi mọi thứ nạn nhân làm đều rơi vào. Bộ nhớ chống
  replay vẫn chặn lần dùng thứ hai của cùng assertion. Chỉ bật khi người dùng
  buộc phải bắt đầu từ dashboard của IdP.
- **`trust_email_for_linking`** cho phép ai kiểm soát một email ở identity
  provider nhận tài khoản có email đó mà chưa có mật khẩu và chưa có
  identity. Chỉ bật cho identity provider thật sự quản lý các địa chỉ đó, kèm
  `allowed_domains`.
- **`PUBLIC_BASE_URL` phải là `https://`** khi chạy thật. Chỉ khi đó cookie
  đăng nhập mới là SameSite=None và Secure; SP entity id, ACS và base URL của
  SCIM đều suy ra từ nó.
- **Token SCIM** tạo, sửa, deactivate và xoá được người dùng của tổ chức: chỉ
  owner tạo và thu hồi, token chỉ hiện một lần và được lưu dạng SHA-256; hãy
  đặt `expires_at` và xoay vòng. Mỗi lần dùng token đều được ghi lại
  (`last_used_at`, `scim_token_id` trong nhật ký hoạt động).
- **Nhận một tên miền** bằng `domain_join` cũng cho SCIM client của tổ chức
  liên kết tài khoản sẵn có của tên miền đó, thu hồi phiên và vô hiệu hoá
  chúng khi tổ chức là nơi duy nhất họ thuộc về.
- **Deactivate và API key**: khi bật `scim_revoke_keys`, các key người dùng
  đã tạo bị thu hồi cùng họ. Key tạo trước migration 025 không có người tạo
  nên vẫn còn; hãy rà soát chúng sau khi nâng cấp.

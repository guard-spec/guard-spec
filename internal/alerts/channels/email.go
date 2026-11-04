// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"text/template"
	"time"
)

// SMTPConfig comes from SMTP_URL and SMTP_FROM:
//
//	smtp://user:pass@host:587   STARTTLS, required unless the host is loopback
//	smtps://user:pass@host:465  implicit TLS
//
// The password is never logged; errors are redacted.
type SMTPConfig struct {
	URL  string
	From string
}

// Enabled reports whether email can be sent.
func (c SMTPConfig) Enabled() bool { return c.URL != "" && c.From != "" }

// Email sends alerts over SMTP. Target (or Config "to") holds the addresses.
type Email struct {
	SMTP SMTPConfig
	// TLS overrides the TLS config (tests trust their own certificate).
	TLS *tls.Config
}

var emailTemplates = map[string]*template.Template{
	"en": template.Must(template.New("en").Parse(`{{.Title}}

{{range .Lines}}{{.}}
{{end}}{{if .Link}}
Open the alert: {{.Link}}
{{end}}
--
Guard Spec alerts. Notifications carry metadata only, never prompt text.
Change what you receive under My account > Notifications.
`)),
	"vi": template.Must(template.New("vi").Parse(`{{.Title}}

{{range .Lines}}{{.}}
{{end}}{{if .Link}}
Mở cảnh báo: {{.Link}}
{{end}}
--
Cảnh báo của Guard Spec. Thông báo chỉ chứa siêu dữ liệu, không bao giờ chứa nội dung prompt.
Thay đổi thông báo bạn nhận tại Tài khoản của tôi > Thông báo.
`)),
}

func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

// BuildEmail renders the message: headers and a base64 UTF-8 text body.
func BuildEmail(from string, to []string, p *Payload, lang, msgID string) ([]byte, error) {
	if _, ok := emailTemplates[lang]; !ok {
		lang = "en"
	}
	s := Render(p, lang)
	var body bytes.Buffer
	if err := emailTemplates[lang].Execute(&body, s); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerSafe(fmt.Sprintf(word(lang, "subject"), s.Title))))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	if msgID != "" {
		fmt.Fprintf(&b, "Message-ID: <%s@guard-spec>\r\n", headerSafe(msgID))
	}
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString(body.Bytes())
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes(), nil
}

func recipients(m *Message) ([]string, error) {
	var raw []string
	if m.Target != "" {
		raw = append(raw, m.Target)
	} else if list, ok := m.Config["to"].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				raw = append(raw, s)
			}
		}
	}
	if len(raw) == 0 {
		return nil, permanent(0, "email: no recipient")
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		a, err := mail.ParseAddress(r)
		if err != nil || strings.ContainsAny(a.Address, "\r\n") {
			return nil, permanent(0, "email: invalid recipient")
		}
		out = append(out, a.Address)
	}
	return out, nil
}

// Send delivers m.
func (e *Email) Send(ctx context.Context, m *Message) (Result, error) {
	if !e.SMTP.Enabled() {
		return Result{}, permanent(0, "email: SMTP_URL and SMTP_FROM are not set")
	}
	to, err := recipients(m)
	if err != nil {
		return Result{}, err
	}
	from, err := mail.ParseAddress(e.SMTP.From)
	if err != nil {
		return Result{}, permanent(0, "email: SMTP_FROM is not a valid address")
	}
	lang := m.Lang
	if l := configString(m.Config, "lang"); l != "" {
		lang = l
	}
	msg, err := BuildEmail(e.SMTP.From, to, &m.Payload, lang, m.IdempotencyKey)
	if err != nil {
		return Result{}, err
	}
	u, err := url.Parse(e.SMTP.URL)
	if err != nil || u.Host == "" {
		return Result{}, permanent(0, "email: SMTP_URL is not valid")
	}
	pass, _ := u.User.Password()
	if err := e.send(ctx, u, from.Address, to, msg); err != nil {
		ce := &Error{Msg: Redact("email: "+err.Error(), pass, u.User.Username())}
		var te *textproto.Error
		if errors.As(err, &te) && te.Code >= 500 {
			ce.Permanent = true
		}
		return Result{}, ce
	}
	return Result{Status: 250}, nil
}

func (e *Email) send(ctx context.Context, u *url.URL, from string, to []string, msg []byte) error {
	host := u.Hostname()
	port := u.Port()
	implicit := u.Scheme == "smtps"
	if port == "" {
		port = "587"
		if implicit {
			port = "465"
		}
	}
	tlsCfg := e.TLS
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*Timeout)
	defer cancel()
	d := &net.Dialer{Timeout: Timeout}
	var conn net.Conn
	var err error
	if implicit {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	} else {
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if !implicit {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		} else if !isLoopback(host) {
			return errors.New("the SMTP server does not offer STARTTLS")
		}
	}
	if u.User != nil {
		pass, _ := u.User.Password()
		if err := c.Auth(smtp.PlainAuth("", u.User.Username(), pass, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

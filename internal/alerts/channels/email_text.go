// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"mime"
	"net/mail"
	"net/url"
	"time"
)

// SendText sends a plain text mail to one address: confirmation codes and
// links of the double opt-in. Errors are redacted.
func (e *Email) SendText(ctx context.Context, to, subject, body string) error {
	if !e.SMTP.Enabled() {
		return permanent(0, "email: SMTP_URL and SMTP_FROM are not set")
	}
	addr, err := mail.ParseAddress(to)
	if err != nil || addr.Address != to {
		return permanent(0, "email: invalid recipient")
	}
	from, err := mail.ParseAddress(e.SMTP.From)
	if err != nil {
		return permanent(0, "email: SMTP_FROM is not a valid address")
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\n", headerSafe(e.SMTP.From), headerSafe(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerSafe(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	u, err := url.Parse(e.SMTP.URL)
	if err != nil || u.Host == "" {
		return permanent(0, "email: SMTP_URL is not valid")
	}
	pass, _ := u.User.Password()
	if err := e.send(ctx, u, from.Address, []string{to}, b.Bytes()); err != nil {
		return &Error{Msg: Redact("email: "+err.Error(), pass, u.User.Username())}
	}
	return nil
}

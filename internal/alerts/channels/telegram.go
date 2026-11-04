// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TelegramAPI is the Bot API origin.
const TelegramAPI = "https://api.telegram.org"

// Telegram sends with the Bot API. The bot token is Message.Secret: the
// channel's secret_env for a group chat, TELEGRAM_BOT_TOKEN for personal
// chats linked with /start.
type Telegram struct {
	Base   string // TelegramAPI; tests point it at a fake
	Client *http.Client
}

// escapeMarkdownV2 escapes every character MarkdownV2 reserves.
func escapeMarkdownV2(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("_*[]()~`>#+-=|{}.!\\", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EscapeMarkdownV2 is escapeMarkdownV2, for tests and the link replies.
func EscapeMarkdownV2(s string) string { return escapeMarkdownV2(s) }

func telegramText(p *Payload, lang string) string {
	s := Render(p, lang)
	var b strings.Builder
	b.WriteString("*" + escapeMarkdownV2(s.Title) + "*")
	for _, l := range s.Lines {
		b.WriteString("\n" + escapeMarkdownV2(l))
	}
	if s.Link != "" {
		// Inside (...) of a link only ) and \ need escaping.
		link := strings.NewReplacer(`\`, `\\`, `)`, `\)`).Replace(s.Link)
		b.WriteString("\n[" + escapeMarkdownV2(word(lang, "open")) + "](" + link + ")")
	}
	return b.String()
}

type telegramResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// Call invokes a Bot API method and decodes its result into out.
func (t *Telegram) Call(ctx context.Context, token, method string, args any, out any) (int, error) {
	if token == "" {
		return 0, permanent(0, "telegram bot token is not set")
	}
	base := t.Base
	if base == "" {
		base = TelegramAPI
	}
	req, err := jsonRequest(ctx, http.MethodPost, base+"/bot"+token+"/"+method, args)
	if err != nil {
		return 0, err
	}
	r, herr := do(t.Client, req, token)
	var tr telegramResponse
	_ = json.Unmarshal(r.body, &tr)
	if herr != nil {
		ce := AsError(herr, token)
		if tr.Parameters.RetryAfter > 0 {
			ce.RetryAfter = time.Duration(tr.Parameters.RetryAfter) * time.Second
		}
		if tr.Description != "" {
			ce.Msg = Redact(fmt.Sprintf("telegram %d: %s", r.status, tr.Description), token)
		}
		return r.status, ce
	}
	if !tr.OK {
		return r.status, permanent(r.status, "%s", Redact("telegram: "+tr.Description, token))
	}
	if out != nil {
		if err := json.Unmarshal(tr.Result, out); err != nil {
			return r.status, &Error{Status: r.status, Msg: "telegram: unexpected answer"}
		}
	}
	return r.status, nil
}

// Send posts the alert to the chat in m.Target, or the channel's chat_id.
func (t *Telegram) Send(ctx context.Context, m *Message) (Result, error) {
	chat := m.Target
	if chat == "" {
		chat = configString(m.Config, "chat_id")
	}
	if chat == "" {
		return Result{}, permanent(0, "telegram: no chat_id")
	}
	var sent struct {
		MessageID int64 `json:"message_id"`
	}
	status, err := t.Call(ctx, m.Secret, "sendMessage", map[string]any{
		"chat_id":                  chat,
		"text":                     telegramText(&m.Payload, m.Lang),
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
	}, &sent)
	if err != nil {
		return Result{}, err
	}
	return Result{Status: status, RemoteID: strconv.FormatInt(sent.MessageID, 10)}, nil
}

// TelegramUpdate is the part of a Bot API Update the linking flow reads.
type TelegramUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Text string `json:"text"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
}

// StartCode returns the code of a private "/start <code>" message, or "".
func (u *TelegramUpdate) StartCode() (chat string, code string) {
	if u.Message == nil || u.Message.Chat.Type != "private" {
		return "", ""
	}
	f := strings.Fields(u.Message.Text)
	if len(f) != 2 || (f[0] != "/start" && !strings.HasPrefix(f[0], "/start@")) {
		return "", ""
	}
	if len(f[1]) > 64 {
		return "", ""
	}
	return strconv.FormatInt(u.Message.Chat.ID, 10), f[1]
}

// GetUpdates long-polls for updates after offset (the polling fallback).
func (t *Telegram) GetUpdates(ctx context.Context, token string, offset int64, wait time.Duration) ([]TelegramUpdate, error) {
	var out []TelegramUpdate
	_, err := t.Call(ctx, token, "getUpdates", map[string]any{
		"offset": offset, "timeout": int(wait.Seconds()), "allowed_updates": []string{"message"},
	}, &out)
	return out, err
}

// GetMe returns the bot's username.
func (t *Telegram) GetMe(ctx context.Context, token string) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	_, err := t.Call(ctx, token, "getMe", map[string]any{}, &me)
	return me.Username, err
}

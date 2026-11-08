// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package outputguard

import (
	"maps"
	"strings"
	"testing"
)

// CountPII reports kinds and counts with the output guard's detectors, and
// never the values.
func TestCountPII(t *testing.T) {
	tests := []struct {
		name string
		text string
		want Counts // nil: nothing found
	}{
		// English
		{"email", "Please write to john.doe@example.com about the invoice.", Counts{KindEmail: 1}},
		{"two emails", "cc: a@example.org, b.c+tag@mail.example.co.uk", Counts{KindEmail: 2}},
		{"card with spaces", "My card is 4111 1111 1111 1111, expiry 12/29.", Counts{KindCard: 1}},
		{"card with dashes", "Charge 5555-5555-5555-4444 please", Counts{KindCard: 1}},
		{"card digits only", "pan=4012888888881881", Counts{KindCard: 1}},
		{"ipv4", "The server at 192.168.1.10 does not answer.", Counts{KindIPv4: 1}},
		{"mixed", "Mail ops@example.com from 10.0.0.1 and 203.0.113.7", Counts{KindEmail: 1, KindIPv4: 2}},

		// Vietnamese
		{"vi phone 10 digits", "Số điện thoại của tôi là 0912345678.", Counts{KindPhone: 1}},
		{"vi phone spaced", "Gọi cho tôi qua số 091 234 5678 nhé", Counts{KindPhone: 1}},
		{"vi phone dotted", "SĐT: 0912.345.678", Counts{KindPhone: 1}},
		{"vi phone dashed", "Hotline 0983-456-789", Counts{KindPhone: 1}},
		{"vi phone +84", "Liên hệ +84 912 345 678 hoặc +84912345679", Counts{KindPhone: 2}},
		{"vi phone 84 without plus", "zalo 84912345678", Counts{KindPhone: 1}},
		{"vi landline", "Tổng đài 02838234567", Counts{KindPhone: 1}},
		{"cccd", "Căn cước công dân số 079203001234 cấp ngày 01/02/2021", Counts{KindCCCD: 1}},
		{"vi mixed", "Tên: Nguyễn Văn An, email an.nguyen@congty.vn, SĐT 0912 345 678, CCCD 001099012345",
			Counts{KindEmail: 1, KindPhone: 1, KindCCCD: 1}},

		// Not personal data
		{"plain prompt", "Summarise the meeting notes in three bullet points.", nil},
		{"vi plain prompt", "Tóm tắt cuộc họp sáng nay giúp tôi trong ba ý chính.", nil},
		{"order number", "Order #A-20231108-7781 was shipped; ticket ORD123456.", nil},
		{"vi order code", "Mã đơn hàng DH-2024-000123, tổng 1.250.000 đồng", nil},
		{"iso timestamp", "Logged at 2026-11-08T10:30:00Z and 2026-11-08 10:31:05+07:00", nil},
		{"unix seconds", "created_at=1731052800", nil},
		{"semver", "Upgrade from v1.2.3 to 1.10.0-rc.1", nil},
		{"amount", "Total: 12,345,678.90 USD", nil},
		{"eleven digits", "account 01234567891", nil},
		{"thirteen digits starting 0", "id 0123456789012", nil},
		{"luhn fails", "4111 1111 1111 1112", nil},
		{"ipv4 out of range", "999.1.1.1", nil},
		{"ipv4 inside a longer dotted run", "OID 1.3.6.1.4.1.311", nil},
		{"at without domain", "meet @ 5pm, ping @alice", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountPII(tt.text)
			if !maps.Equal(got, tt.want) || (tt.want == nil) != (got == nil) {
				t.Errorf("CountPII(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

// Four dotted numbers each up to 255 read as an IPv4 address, so a version
// such as 1.2.3.4 counts as ipv4. Rules that should not act on addresses can
// test the other kinds.
func TestCountPIIVersionLooksLikeIPv4(t *testing.T) {
	if got := CountPII("Requires Windows 10.0.19041.1 or OpenSSL 1.1.1.1"); got[KindIPv4] != 1 {
		t.Errorf("got %v, want one ipv4 (10.0.19041.1 is not one, 1.1.1.1 is)", got)
	}
	if got := CountPII("version 1.2.3.4"); got[KindIPv4] != 1 {
		t.Errorf("got %v, want 1.2.3.4 as ipv4", got)
	}
}

// A stretch of text counts once: a 12-digit citizen ID is not also a phone
// number, and the overlap rule is the output guard's.
func TestCountPIIMatchesOutputGuard(t *testing.T) {
	texts := []string{
		"CCCD 079203001234 và SĐT 0912345678",
		"card 4111111111111111 ip 8.8.8.8 mail x@y.io",
		"0912345678@example.com",
		"+84 912 345 678 / 192.168.0.1 / 001099012345",
	}
	g := New(Config{RedactPII: true, RedactIPv4: true})
	for _, text := range texts {
		counts := Counts{}
		out := g.ForRequest("").Text(text, counts)
		got := CountPII(text)
		if got.Total() != counts.Total() || !maps.Equal(got, counts) {
			t.Errorf("%q: CountPII = %v, output guard redacted %v (%q)", text, got, counts, out)
		}
	}
}

// The result holds kinds and counts, never the text found.
func TestCountPIIKeepsNoValues(t *testing.T) {
	text := "john.doe@example.com 0912345678 4111111111111111 079203001234 10.1.2.3"
	got := CountPII(text)
	if len(got) != len(PIIKinds) {
		t.Fatalf("got %v, want every kind once", got)
	}
	for kind, n := range got {
		if n != 1 || strings.Contains(text, kind) {
			t.Errorf("kind %q count %d", kind, n)
		}
	}
}

// BenchmarkCountPII is the cost of the input-side check per request text.
func BenchmarkCountPII(b *testing.B) {
	base := "Please summarise the following meeting notes for me and list the action items. " +
		"Thời tiết Hà Nội hôm nay thế nào, gợi ý vài chỗ đi chơi cuối tuần. "
	for _, size := range []struct {
		name  string
		bytes int
	}{{"2k", 2 << 10}, {"20k", 20 << 10}} {
		clean := strings.Repeat(base, size.bytes/len(base)+1)[:size.bytes]
		withPII := clean[:size.bytes-80] + " mail an.nguyen@congty.vn, SĐT 0912 345 678."
		for _, c := range []struct{ name, text string }{{"clean", clean}, {"pii", withPII}} {
			b.Run(size.name+"_"+c.name, func(b *testing.B) {
				b.SetBytes(int64(len(c.text)))
				b.ReportAllocs()
				for b.Loop() {
					CountPII(c.text)
				}
			})
		}
	}
}

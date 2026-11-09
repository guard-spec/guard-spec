// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package indirect

import "testing"

func TestMaxScanTokensSetting(t *testing.T) {
	s, err := ParseSettings([]byte(`{"max_scan_tokens":20000}`))
	if err != nil || s.MaxScanTokens == nil || *s.MaxScanTokens != 20000 {
		t.Fatalf("parse: %+v %v", s, err)
	}
	// The org can only lower the gateway's cap; with the gateway at 0 its
	// cap is the only one.
	for gw, want := range map[int]int{0: 20000, 10000: 10000, 50000: 20000} {
		if got := s.ScanTokens(gw); got != want {
			t.Errorf("gateway %d: %d, want %d", gw, got, want)
		}
	}
	if got := (Settings{}).ScanTokens(7); got != 7 {
		t.Errorf("unset: %d", got)
	}
	for _, raw := range []string{`{"max_scan_tokens":0}`, `{"max_scan_tokens":-5}`, `{"max_scan_tokens":10000001}`, `{"max_scan_tokens":"1"}`} {
		if _, err := ParseSettings([]byte(raw)); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

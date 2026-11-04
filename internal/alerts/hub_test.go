// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"testing"

	"github.com/google/uuid"
)

func TestHubSignals(t *testing.T) {
	user, a, b := uuid.New(), uuid.New(), uuid.New()
	cases := []struct {
		payload string
		want    Signal
	}{
		{user.String(), Signal{}},
		{ReadPayload(user, nil, true), Signal{Read: &ReadEvent{All: true}}},
		{ReadPayload(user, []uuid.UUID{a, b}, false), Signal{Read: &ReadEvent{IDs: []uuid.UUID{a, b}}}},
		{ReadPayload(user, make([]uuid.UUID, maxReadIDs+1), false), Signal{Refresh: true}},
	}
	for _, tc := range cases {
		u, s, ok := ParseSignal(tc.payload)
		if !ok || u != user || s.Refresh != tc.want.Refresh || (s.Read == nil) != (tc.want.Read == nil) {
			t.Fatalf("%q: %v %+v", tc.payload, ok, s)
		}
		if s.Read != nil && (s.Read.All != tc.want.Read.All || len(s.Read.IDs) != len(tc.want.Read.IDs)) {
			t.Fatalf("%q: %+v", tc.payload, s.Read)
		}
	}
	if len(ReadPayload(user, make([]uuid.UUID, maxReadIDs), false)) > 8000 {
		t.Fatal("payload over the NOTIFY limit")
	}
	if _, _, ok := ParseSignal("not-a-user"); ok {
		t.Fatal("bad payload accepted")
	}
	h := NewHub()
	ch, done, err := h.Subscribe(user)
	if err != nil {
		t.Fatal(err)
	}
	h.Publish(user, Signal{Read: &ReadEvent{All: true}})
	if s := <-ch; s.Read == nil || !s.Read.All {
		t.Fatal("signal not delivered")
	}
	for i := 0; i < MaxStreamsPerUser-1; i++ {
		if _, _, err := h.Subscribe(user); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := h.Subscribe(user); err == nil {
		t.Fatal("over the per-user stream limit")
	}
	done()
	if _, _, err := h.Subscribe(user); err != nil {
		t.Fatal("a closed stream still counts")
	}
}

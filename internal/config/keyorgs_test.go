package config

import (
	"testing"

	"github.com/google/uuid"
)

func TestKeyOrgs(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	k, err := ParseKeyOrgs(" UPSTREAM_KEY_MAIN=* ; UPSTREAM_KEY_ACME=" + a.String() + ", " + b.String() + ";")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		org  uuid.UUID
		want bool
	}{
		{"UPSTREAM_KEY_MAIN", a, true},
		{"UPSTREAM_KEY_MAIN", uuid.New(), true},
		{"UPSTREAM_KEY_ACME", a, true},
		{"UPSTREAM_KEY_ACME", b, true},
		{"UPSTREAM_KEY_ACME", uuid.New(), false},
		{"UPSTREAM_KEY_OTHER", a, false},
		{"JWT_SECRET", a, false},
	} {
		if got := k.Allows(tt.name, tt.org); got != tt.want {
			t.Errorf("%s for %s = %v", tt.name, tt.org, got)
		}
	}
	if k.Check("", a) != nil || k.Check("UPSTREAM_KEY_ACME", uuid.New()) == nil {
		t.Error("Check")
	}

	// The default allows nothing; * has to be written.
	empty, err := ParseKeyOrgs("")
	if err != nil || empty.Allows("UPSTREAM_KEY_MAIN", a) {
		t.Errorf("empty allows: %v", err)
	}
	var zero KeyOrgs
	if zero.Allows("UPSTREAM_KEY_MAIN", a) {
		t.Error("zero value allows")
	}
	for _, bad := range []string{"UPSTREAM_KEY_MAIN", "JWT_SECRET=*", "UPSTREAM_KEY_MAIN=acme", "UPSTREAM_KEY_MAIN=", "upstream_key_x=*"} {
		if _, err := ParseKeyOrgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

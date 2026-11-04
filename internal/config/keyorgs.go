package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// UpstreamKeyVarRe is the form of a variable that may hold a named upstream's
// key. Other variables (JWT_SECRET, DATABASE_URL) can never be named.
var UpstreamKeyVarRe = regexp.MustCompile(`^UPSTREAM_KEY_[A-Z0-9_]{1,64}$`)

// KeyOrgs is the operator's allowlist UPSTREAM_KEY_ORGS: which organizations
// may name which UPSTREAM_KEY_* variable as an upstream's api_key_env. Without
// it any org could point an upstream at a host it controls and receive the
// operator's key, so the zero value allows nothing.
//
// Format: UPSTREAM_KEY_MAIN=*;UPSTREAM_KEY_ACME=<org-uuid>,<org-uuid>
// "*" (every organization) must be written out.
type KeyOrgs struct {
	all  map[string]bool
	orgs map[string]map[uuid.UUID]bool
}

// ParseKeyOrgs parses UPSTREAM_KEY_ORGS. An empty value allows no variable.
func ParseKeyOrgs(s string) (KeyOrgs, error) {
	k := KeyOrgs{all: map[string]bool{}, orgs: map[string]map[uuid.UUID]bool{}}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !ok || !UpstreamKeyVarRe.MatchString(name) {
			return KeyOrgs{}, fmt.Errorf("UPSTREAM_KEY_ORGS: %q must be UPSTREAM_KEY_<NAME>=* or UPSTREAM_KEY_<NAME>=<org-id>,<org-id>", entry)
		}
		list = strings.TrimSpace(list)
		if list == "*" {
			k.all[name] = true
			continue
		}
		for _, item := range strings.Split(list, ",") {
			id, err := uuid.Parse(strings.TrimSpace(item))
			if err != nil {
				return KeyOrgs{}, fmt.Errorf("UPSTREAM_KEY_ORGS: %s: %q is not an organization id or *", name, item)
			}
			if k.orgs[name] == nil {
				k.orgs[name] = map[uuid.UUID]bool{}
			}
			k.orgs[name][id] = true
		}
	}
	return k, nil
}

// MustParseKeyOrgs is ParseKeyOrgs for tests and constants.
func MustParseKeyOrgs(s string) KeyOrgs {
	k, err := ParseKeyOrgs(s)
	if err != nil {
		panic(err)
	}
	return k
}

// Allows reports whether org may use the key variable name.
func (k KeyOrgs) Allows(name string, org uuid.UUID) bool {
	if !UpstreamKeyVarRe.MatchString(name) {
		return false
	}
	return k.all[name] || k.orgs[name][org]
}

// Check returns an error explaining why org may not use name, or nil.
func (k KeyOrgs) Check(name string, org uuid.UUID) error {
	if name == "" || k.Allows(name, org) {
		return nil
	}
	return fmt.Errorf("api_key_env %s is not allowed for this organization; the operator lists usable key variables "+
		"per organization in UPSTREAM_KEY_ORGS (for example %s=%s)", name, name, org)
}

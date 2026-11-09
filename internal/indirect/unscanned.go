// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package indirect

import (
	"fmt"
	"strings"
)

// Unscanned content (RF-c18516ae): parts of a request the gateway forwards
// but cannot read (images, files, audio), so an injection inside them is not
// classified. UNSCANNED_PARTS says what the gateway does with them.
const (
	UnscannedAllow = "allow" // forward, count in metrics only
	UnscannedLog   = "log"   // forward, tag the audit row (the default)
	UnscannedBlock = "block" // refuse the request (400 unscanned_content)
)

// Kinds of unscanned parts, in the order the audit tags and
// input.unscanned.kinds list them. other: a part with no text of a type the
// gateway does not know, so a new provider part type is not missed.
var UnscannedKinds = []string{"image", "file", "audio", "other"}

var unscannedRank = map[string]int{UnscannedAllow: 0, UnscannedLog: 1, UnscannedBlock: 2}

// ParseUnscannedMode checks an UNSCANNED_PARTS value; "" is the default, log.
func ParseUnscannedMode(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return UnscannedLog, nil
	}
	if _, ok := unscannedRank[s]; !ok {
		return "", fmt.Errorf("UNSCANNED_PARTS must be allow, log or block, not %q", s)
	}
	return s, nil
}

// Unscanned returns the mode for the org: its unscanned_parts when that is
// stricter than the gateway's, else the gateway's. An org can only tighten.
func (s Settings) Unscanned(gateway string) string {
	if s.UnscannedParts != nil && unscannedRank[*s.UnscannedParts] > unscannedRank[gateway] {
		return *s.UnscannedParts
	}
	return gateway
}

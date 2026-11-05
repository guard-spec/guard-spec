// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Package alerts turns events into alerts and notifications
// (docs/alerts.md): the rule engine, recipient resolution, the outbox
// dispatcher and the worker that runs them in the control plane.
package alerts

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/events"
	"github.com/guard-spec/guard-spec/internal/policy"
)

// Severities, lowest first.
var severityRank = map[string]int{events.Info: 1, events.Warning: 2, events.Critical: 3}

// ValidSeverity reports whether s is info, warning or critical.
func ValidSeverity(s string) bool { return severityRank[s] > 0 }

// AtLeast reports whether sev is at or above min.
func AtLeast(sev, min string) bool {
	return severityRank[sev] >= severityRank[min] && severityRank[sev] > 0
}

// Fields are what a rule condition can name: the event's type, severity and
// project, and its attributes. Attributes an event lacks read as "", 0 or [].
var Fields = policy.FieldSet{
	"type":              policy.String,
	"severity":          policy.String,
	"project_id":        policy.String,
	"attrs.request_id":  policy.String,
	"attrs.categories":  policy.StringList,
	"attrs.category":    policy.String,
	"attrs.score":       policy.Double,
	"attrs.layer":       policy.String,
	"attrs.decision":    policy.String,
	"attrs.api_key_id":  policy.String,
	"attrs.model":       policy.String,
	"attrs.upstream_id": policy.String,
	"attrs.status":      policy.Int,
	"attrs.error_kind":  policy.String,
	"attrs.user_id":     policy.String,
	"attrs.email_hash":  policy.String,
	"attrs.ip":          policy.String,
	"attrs.reason":      policy.String,
	"attrs.actor_id":    policy.String,
	"attrs.from":        policy.String,
	"attrs.to":          policy.String,
	"attrs.provider_id": policy.String,
	"attrs.policy_id":   policy.String,
	"attrs.action":      policy.String,
}

// GroupByKeys are the allowed group_by entries.
var GroupByKeys = []string{"project_id", "attrs.category", "attrs.upstream_id"}

// Recipients of a rule. Roles are org roles (viewer, member, admin, owner).
type Recipients struct {
	UserIDs  []uuid.UUID `json:"user_ids"`
	GroupIDs []uuid.UUID `json:"group_ids"`
	Roles    []string    `json:"roles"`
}

// QuietHours mutes or delays notifications in a daily window, in tz.
type QuietHours struct {
	TZ             string `json:"tz"`
	Start          string `json:"start"` // "22:00"
	End            string `json:"end"`   // "07:00"
	Mode           string `json:"mode"`  // suppress or delay
	CriticalBypass bool   `json:"critical_bypass"`
}

// Rule is a row of alert_rules.
type Rule struct {
	ID              uuid.UUID   `json:"id"`
	OrgID           uuid.UUID   `json:"-"`
	Name            string      `json:"name"`
	Enabled         bool        `json:"enabled"`
	EventTypes      []string    `json:"event_types"`
	Condition       string      `json:"condition"`
	ConditionCEL    string      `json:"-"`
	Threshold       int         `json:"threshold"`
	WindowSeconds   int         `json:"window_seconds"`
	Severity        string      `json:"severity"`
	ThrottleSeconds int         `json:"throttle_seconds"`
	GroupBy         []string    `json:"group_by"`
	QuietHours      *QuietHours `json:"quiet_hours"`
	AutoResolve     bool        `json:"auto_resolve"`
	Recipients      Recipients  `json:"recipients"`
	ChannelIDs      []uuid.UUID `json:"channel_ids"`
	CreatedBy       *uuid.UUID  `json:"created_by"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// Defaults of a new rule.
const (
	DefaultThreshold = 1
	DefaultWindow    = 300
	DefaultThrottle  = 900
	MaxRecipients    = 200
)

var eventTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// ValidEventType accepts the contract's types and activity.* types.
func ValidEventType(t string) bool {
	return len(t) <= 80 && eventTypeRe.MatchString(t) &&
		(slices.Contains(events.Types, t) || strings.HasPrefix(t, "activity."))
}

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ValidationError is a rule the API refuses (400). Position is set for a
// condition parse error.
type ValidationError struct {
	Message  string
	Position *int
}

func (e *ValidationError) Error() string { return e.Message }

func invalid(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

// Validate checks r, fills defaults the caller left zero (threshold, window,
// severity) and compiles its condition into ConditionCEL.
func Validate(r *Rule) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || utf8.RuneCountInString(r.Name) > 100 {
		return invalid("name is required (at most 100 characters)")
	}
	if len(r.EventTypes) == 0 || len(r.EventTypes) > 20 {
		return invalid("event_types needs 1 to 20 event types")
	}
	seen := map[string]bool{}
	types := r.EventTypes[:0:0]
	for _, t := range r.EventTypes {
		if !ValidEventType(t) {
			return invalid("unknown event type %q", t)
		}
		if !seen[t] {
			seen[t] = true
			types = append(types, t)
		}
	}
	r.EventTypes = types
	if r.Threshold == 0 {
		r.Threshold = DefaultThreshold
	}
	if r.Threshold < 1 || r.Threshold > 100000 {
		return invalid("threshold must be between 1 and 100000")
	}
	if r.WindowSeconds == 0 {
		r.WindowSeconds = DefaultWindow
	}
	if r.WindowSeconds < 60 || r.WindowSeconds > 86400 {
		return invalid("window_seconds must be between 60 and 86400")
	}
	if r.Severity == "" {
		r.Severity = events.Warning
	}
	if !ValidSeverity(r.Severity) {
		return invalid("severity must be info, warning or critical")
	}
	if r.ThrottleSeconds < 0 || r.ThrottleSeconds > 604800 {
		return invalid("throttle_seconds must be between 0 and 604800")
	}
	if r.GroupBy == nil {
		r.GroupBy = []string{}
	}
	for _, g := range r.GroupBy {
		if !slices.Contains(GroupByKeys, g) {
			return invalid("group_by may hold %s", strings.Join(GroupByKeys, ", "))
		}
	}
	if q := r.QuietHours; q != nil {
		if _, err := time.LoadLocation(q.TZ); err != nil || q.TZ == "" {
			return invalid("quiet_hours.tz must be an IANA time zone such as Asia/Ho_Chi_Minh")
		}
		if !hhmmRe.MatchString(q.Start) || !hhmmRe.MatchString(q.End) || q.Start == q.End {
			return invalid("quiet_hours.start and end are different times such as 22:00 and 07:00")
		}
		if q.Mode != "suppress" && q.Mode != "delay" {
			return invalid("quiet_hours.mode must be suppress or delay")
		}
	}
	rc := &r.Recipients
	if rc.UserIDs == nil {
		rc.UserIDs = []uuid.UUID{}
	}
	if rc.GroupIDs == nil {
		rc.GroupIDs = []uuid.UUID{}
	}
	if rc.Roles == nil {
		rc.Roles = []string{}
	}
	if len(rc.UserIDs)+len(rc.GroupIDs)+len(rc.Roles) > MaxRecipients {
		return invalid("at most %d recipients", MaxRecipients)
	}
	for _, role := range rc.Roles {
		if !slices.Contains([]string{"viewer", "member", "admin", "owner"}, role) {
			return invalid("recipients.roles may hold viewer, member, admin and owner")
		}
	}
	if r.ChannelIDs == nil {
		r.ChannelIDs = []uuid.UUID{}
	}
	if len(r.ChannelIDs) > 20 {
		return invalid("at most 20 channel_ids")
	}
	r.Condition = strings.TrimSpace(r.Condition)
	r.ConditionCEL = ""
	if r.Condition != "" {
		expr, err := policy.ParseConditionIn(r.Condition, Fields)
		if err != nil {
			ve := &ValidationError{Message: "condition: " + err.Error()}
			if pe, ok := policy.AsParseError(err); ok {
				ve.Message = "condition: " + pe.Message
				pos := pe.Position
				ve.Position = &pos
			}
			return ve
		}
		if _, err := policy.CompileCondition(expr, Fields); err != nil {
			return invalid("condition: %v", err)
		}
		r.ConditionCEL = expr
	}
	return nil
}

// Vars builds the condition input of an event: every field of Fields, with
// zero values for attributes the event lacks.
func Vars(ev *events.Event) map[string]any {
	v := make(map[string]any, len(Fields))
	for name, typ := range Fields {
		switch typ {
		case policy.StringList:
			v[name] = []string{}
		case policy.Double:
			v[name] = 0.0
		case policy.Int:
			v[name] = int64(0)
		default:
			v[name] = ""
		}
	}
	v["type"], v["severity"] = ev.Type, ev.Severity
	if ev.ProjectID != nil {
		v["project_id"] = ev.ProjectID.String()
	}
	for k, raw := range ev.Attrs {
		name := "attrs." + k
		typ, ok := Fields[name]
		if !ok {
			continue
		}
		switch typ {
		case policy.StringList:
			v[name] = toStrings(raw)
		case policy.Double:
			v[name] = toFloat(raw)
		case policy.Int:
			v[name] = int64(toFloat(raw))
		default:
			v[name] = toString(raw)
		}
	}
	if c, _ := v["attrs.category"].(string); c == "" {
		if cats, _ := v["attrs.categories"].([]string); len(cats) > 0 {
			v["attrs.category"] = cats[0]
		}
	}
	return v
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, i := range x {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return []string{}
		}
		return []string{x}
	}
	return []string{}
}

// DedupeKey is the rule's grouping of an event: "" without group_by, else
// "key=value" pairs in group_by order joined by "|", and the same as a map.
func DedupeKey(groupBy []string, vars map[string]any) (string, map[string]string) {
	group := map[string]string{}
	if len(groupBy) == 0 {
		return "", group
	}
	parts := make([]string, 0, len(groupBy))
	for _, g := range groupBy {
		val, _ := vars[g].(string)
		group[g] = val
		parts = append(parts, g+"="+val)
	}
	return strings.Join(parts, "|"), group
}

// safeAttrKeys are the attributes copied into notification payloads. Any
// other attribute is dropped, so no free text reaches a receiver.
var safeAttrKeys = func() map[string]bool {
	m := map[string]bool{}
	for name := range Fields {
		if k, ok := strings.CutPrefix(name, "attrs."); ok {
			m[k] = true
		}
	}
	return m
}()

// SafeAttrs keeps the known metadata attributes, with strings capped at 200
// characters and lists at 20 items.
func SafeAttrs(attrs map[string]any) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !safeAttrKeys[k] {
			continue
		}
		switch x := attrs[k].(type) {
		case string:
			out[k] = capString(x, 200)
		case float64, float32, int, int64, bool, nil:
			out[k] = x
		case []any:
			list := []string{}
			for _, i := range x {
				if s, ok := i.(string); ok && len(list) < 20 {
					list = append(list, capString(s, 100))
				}
			}
			out[k] = list
		case []string:
			list := []string{}
			for _, s := range x {
				if len(list) < 20 {
					list = append(list, capString(s, 100))
				}
			}
			out[k] = list
		}
	}
	return out
}

func capString(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

var errNoRule = errors.New("rule not found")

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func parseUUID(s string) (uuid.UUID, error) { return uuid.Parse(s) }

// Pagination of list endpoints: ?limit=50&cursor=<opaque>. limit defaults to
// 50, at most 200. The cursor is the sort key of the last row returned
// (base64url JSON), never an offset, so rows inserted meanwhile do not shift
// the pages. The answer is {"items": [...], "next_cursor": "..."|null, "total": n}
// (total only where it is cheap).
//
// Endpoints that existed before keep their old shape ({"data": [...]}) when
// the request has neither limit nor cursor, for one release.

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

// pageCursor is the keyset position: a sort value (a time or a string) and
// the row's id as the tie breaker.
type pageCursor struct {
	T  *time.Time `json:"t,omitempty"`
	S  *string    `json:"s,omitempty"`
	ID string     `json:"id"`
}

type pageReq struct {
	Limit     int
	After     *pageCursor
	Enveloped bool // limit or cursor was given (always true for new endpoints)
}

var (
	errBadCursor = errors.New("invalid cursor")
	errBadLimit  = fmt.Errorf("limit must be between 1 and %d", maxPageLimit)
)

// isPageError reports an invalid limit or cursor (a 400).
func isPageError(err error) bool { return errors.Is(err, errBadCursor) || errors.Is(err, errBadLimit) }

// parsePage reads limit and cursor. legacy: the endpoint answered without an
// envelope before pagination.
func parsePage(c *fiber.Ctx, legacy bool) (pageReq, error) {
	p := pageReq{Limit: defaultPageLimit, Enveloped: !legacy}
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return p, errBadLimit
		}
		p.Limit = min(n, maxPageLimit)
		p.Enveloped = true
	}
	if raw := c.Query("cursor"); raw != "" {
		p.Enveloped = true
		data, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(data) > 1024 {
			return p, errBadCursor
		}
		var cur pageCursor
		if err := json.Unmarshal(data, &cur); err != nil || cur.ID == "" || (cur.T == nil) == (cur.S == nil) {
			return p, errBadCursor
		}
		p.After = &cur
	}
	return p, nil
}

func encodeCursor(cur pageCursor) string {
	data, _ := json.Marshal(cur)
	return base64.RawURLEncoding.EncodeToString(data)
}

func timeCursor(t time.Time, id string) pageCursor { return pageCursor{T: &t, ID: id} }

func stringCursor(s, id string) pageCursor { return pageCursor{S: &s, ID: id} }

// afterTime returns the cursor's time and id, or ok false when the request
// has no cursor. A cursor of the other kind is invalid.
func (p pageReq) afterTime() (t time.Time, id string, ok bool, err error) {
	if p.After == nil {
		return time.Time{}, "", false, nil
	}
	if p.After.T == nil {
		return time.Time{}, "", false, errBadCursor
	}
	return *p.After.T, p.After.ID, true, nil
}

func (p pageReq) afterString() (s, id string, ok bool, err error) {
	if p.After == nil {
		return "", "", false, nil
	}
	if p.After.S == nil {
		return "", "", false, errBadCursor
	}
	return *p.After.S, p.After.ID, true, nil
}

// keyset describes the sort order of a list: a time or text column, then a
// unique tie breaker (uuid or text).
type keyset struct {
	sort, id string
	desc     bool
	textSort bool   // the sort column is text, not a timestamp
	idType   string // "uuid" or "text"
}

// where returns the condition selecting the rows after the cursor ("" without
// one), numbering its parameters after args, and the extended args.
func (k keyset) where(p pageReq, args []any) (string, []any, error) {
	var sortVal any
	var id string
	var ok bool
	var err error
	if k.textSort {
		var s string
		s, id, ok, err = p.afterString()
		sortVal = s
	} else {
		var t time.Time
		t, id, ok, err = p.afterTime()
		sortVal = t
	}
	if err != nil || !ok {
		return "", args, err
	}
	op := ">"
	if k.desc {
		op = "<"
	}
	idType := k.idType
	if idType == "" {
		idType = "uuid"
	}
	if idType == "uuid" {
		if _, perr := parseUUID(id); perr != nil {
			return "", args, errBadCursor
		}
	}
	cond := fmt.Sprintf(" AND (%s, %s) %s ($%d, $%d::%s)", k.sort, k.id, op, len(args)+1, len(args)+2, idType)
	return cond, append(args, sortVal, id), nil
}

// orderLimit is the ORDER BY of the keyset, with LIMIT limit+1 when the
// request is paged.
func (k keyset) orderLimit(p pageReq) string {
	dir := "ASC"
	if k.desc {
		dir = "DESC"
	}
	s := fmt.Sprintf(" ORDER BY %s %s, %s %s", k.sort, dir, k.id, dir)
	if p.Enveloped {
		s += fmt.Sprintf(" LIMIT %d", p.Limit+1)
	}
	return s
}

// page trims rows fetched with limit+1 to the page and returns the next
// cursor (nil on the last page). key returns a row's cursor.
func page[T any](rows []T, limit int, key func(T) pageCursor) ([]T, *string) {
	if len(rows) <= limit {
		return rows, nil
	}
	rows = rows[:limit]
	next := encodeCursor(key(rows[len(rows)-1]))
	return rows, &next
}

// pageJSON writes the envelope. total < 0 omits it.
func pageJSON[T any](c *fiber.Ctx, items []T, next *string, total int64) error {
	out := fiber.Map{"items": items, "next_cursor": next}
	if total >= 0 {
		out["total"] = total
	}
	return c.JSON(out)
}

// likePattern makes a search term an ILIKE pattern that matches it anywhere,
// with its own wildcards escaped.
func likePattern(q string) string {
	return "%" + likeEscape(strings.TrimSpace(q)) + "%"
}

// likeEscape escapes LIKE's wildcards (and its escape character) in s.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// cappedTotalLimit bounds the counts of the audit and activity logs.
const cappedTotalLimit = 10_000

// cappedCount counts the rows of "FROM ... WHERE ..." (from) up to
// cappedTotalLimit, and reports whether there are more.
func cappedCount(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, from string, args []any) (int64, bool, error) {
	var n int64
	err := q.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM (SELECT 1 %s LIMIT %d) x`, from, cappedTotalLimit+1), args...).
		Scan(&n)
	if n > cappedTotalLimit {
		return cappedTotalLimit, true, err
	}
	return n, false, err
}

func badPage(c *fiber.Ctx, err error) error {
	return c.Status(400).JSON(fiber.Map{"error": err.Error()})
}

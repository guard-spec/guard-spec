// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/metrics"
)

// Per-organization input settings (RF-113cd269; the rules are in
// internal/indirect/input.go, the API in the control plane's
// input_settings.go). The gateway reads them with the org's guard settings
// (org_input_settings, dbSettingsLoader). An org without them is served
// exactly as before: PDF_EXTRACT, UNSCANNED_PARTS and MAX_SCAN_TOKENS alone.
//
// Every image, file and audio part gets a type, detected from its content
// (the first bytes: %PDF-, the PNG and JPEG signatures, an OOXML zip, ...)
// and checked against what the part declares (its media type, the data
// URL's type, its file name's extension, an audio format): types are never
// taken from a declaration alone. The types are input.files.types for
// policies. With settings, the org's rules then apply, before anything is
// scanned:
//
//   - text_only refuses every image, file and audio part: 415.
//   - hybrid refuses a part whose type is not in allowed_file_types, whose
//     content does not match its declaration, or that the gateway cannot
//     check (a url or file id): 415.
//   - an allowed file the gateway cannot read (no text layer, encrypted,
//     damaged, over a limit, PDF_EXTRACT off) is refused (422) under
//     unreadable_file_action block, or forwarded as an unscanned part under
//     pass, its audit row tagged (UNSCANNED_PARTS=block still refuses it).
//   - max_input_tokens refuses a request with more tokens of text to scan:
//     413, counted as MAX_SCAN_TOKENS counts them.
//
// Refusals are tagged input:refused=<reason> and counted in
// guardspec_gateway_input_refused_total{reason}.

// layerInput is the layer of a request the org's input settings refused.
const layerInput = "input"

// Refusal reasons: the metric label and the input:refused tag.
const (
	refuseTextOnly       = "text_only"
	refuseTypeNotAllowed = "type_not_allowed"
	refuseTypeMismatch   = "type_mismatch"
	refuseNotInline      = "not_inline"
	refuseUnreadable     = "unreadable"
	refuseMaxTokens      = "max_input_tokens"
)

// File types the gateway detects; fileRemote is a part it does not receive
// (a url or file id), fileUnknown content it does not recognize.
const (
	fileRemote  = "remote"
	fileUnknown = "unknown"
)

// inputRefusal is a request refused by the org's input settings.
type inputRefusal struct {
	status  int
	reason  string // refuse*
	code    string // the error code of the response
	message string
}

func (e *inputRefusal) Error() string { return e.message }

// convertHint ends every file refusal: what the application should do.
const convertHint = " Convert files to text in your application and send the text instead."

func refuseFiles(kind, typ string) *inputRefusal {
	return &inputRefusal{status: fiber.StatusUnsupportedMediaType, reason: refuseTextOnly, code: "files_not_accepted",
		message: fmt.Sprintf("This organization accepts text only: the request contains %s (%s).", partNoun(kind), typ) + convertHint}
}

func refuseType(typ string, allowed []string) *inputRefusal {
	list := "none"
	if len(allowed) > 0 {
		list = strings.Join(allowed, ", ")
	}
	return &inputRefusal{status: fiber.StatusUnsupportedMediaType, reason: refuseTypeNotAllowed, code: "file_type_not_allowed",
		message: fmt.Sprintf("This organization does not accept %s files (allowed: %s).", typ, list) + convertHint}
}

func refuseMismatch(declared, typ string) *inputRefusal {
	return &inputRefusal{status: fiber.StatusUnsupportedMediaType, reason: refuseTypeMismatch, code: "file_type_mismatch",
		message: fmt.Sprintf("A file declares %s but its content is %s: the declared type must match the content.",
			strings.TrimPrefix(declared, "?"), typ)}
}

func refuseRemote() *inputRefusal {
	return &inputRefusal{status: fiber.StatusUnsupportedMediaType, reason: refuseNotInline, code: "file_not_inline",
		message: "This organization accepts files only sent inline (base64 or a data URL), so that the gateway can check them: " +
			"a url or file id cannot be checked." + convertHint}
}

func refuseUnreadableFile(reason string) *inputRefusal {
	return &inputRefusal{status: fiber.StatusUnprocessableEntity, reason: refuseUnreadable, code: "file_unreadable",
		message: "The gateway could not read the text of a file (" + reason + ") and this organization refuses such files." + convertHint}
}

func refuseTokens(limit int) *inputRefusal {
	return &inputRefusal{status: fiber.StatusRequestEntityTooLarge, reason: refuseMaxTokens, code: "max_input_tokens_exceeded",
		message: fmt.Sprintf("Request blocked: it has more than %d tokens of input, this organization's max_input_tokens.", limit)}
}

// partNoun names a part kind in a refusal.
func partNoun(kind string) string {
	switch unscannedKind(kind) {
	case "image":
		return "an image"
	case "audio":
		return "audio"
	}
	return "a file"
}

// mediaTypes maps declared media types to file types.
var mediaTypes = map[string]string{
	"application/pdf": "pdf",
	"image/png":       "png", "image/jpeg": "jpeg", "image/jpg": "jpeg", "image/gif": "gif", "image/webp": "webp",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   "docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         "xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
	"application/zip": "zip", "application/x-zip-compressed": "zip",
	"audio/wav": "wav", "audio/x-wav": "wav", "audio/wave": "wav", "audio/vnd.wave": "wav",
	"audio/mpeg": "mp3", "audio/mp3": "mp3", "audio/ogg": "ogg", "audio/flac": "flac", "audio/x-flac": "flac",
}

// extensions maps file name extensions (and audio formats) to file types.
var extensions = map[string]string{
	"pdf": "pdf", "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif", "webp": "webp",
	"docx": "docx", "xlsx": "xlsx", "pptx": "pptx", "zip": "zip",
	"wav": "wav", "mp3": "mp3", "ogg": "ogg", "flac": "flac",
}

// declaredMedia is the type a media type claims: a known type, "?<media
// type>" for one the gateway does not know, "" for none.
func declaredMedia(mt string) string {
	mt = strings.ToLower(strings.TrimSpace(strings.SplitN(mt, ";", 2)[0]))
	if mt == "" {
		return ""
	}
	if t, ok := mediaTypes[mt]; ok {
		return t
	}
	return "?" + mt
}

// declaredExt is the type a file name or audio format claims, like
// declaredMedia.
func declaredExt(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimSpace(name)), "."))
	if ext == "" {
		return ""
	}
	if t, ok := extensions[ext]; ok {
		return t
	}
	return "?" + ext
}

// sniffBytes is how much of a file the type detection reads.
const sniffBytes = 6 << 10

// sniff detects a file type from the first bytes of its content.
func sniff(b []byte) string {
	switch {
	case isPDFBytes(b):
		return "pdf"
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "gif"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WAVE":
		return "wav"
	case bytes.HasPrefix(b, []byte("OggS")):
		return "ogg"
	case bytes.HasPrefix(b, []byte("fLaC")):
		return "flac"
	case bytes.HasPrefix(b, []byte("ID3")), len(b) >= 2 && b[0] == 0xFF && b[1]&0xE0 == 0xE0:
		return "mp3"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		// An Office Open XML file is a zip whose entries name their part.
		switch {
		case bytes.Contains(b, []byte("word/")):
			return "docx"
		case bytes.Contains(b, []byte("xl/")):
			return "xlsx"
		case bytes.Contains(b, []byte("ppt/")):
			return "pptx"
		}
		return "zip"
	}
	return fileUnknown
}

// sniffBase64 detects the type of base64 content (plain, or the data of a
// data URL) from its first bytes, without decoding the rest.
func sniffBase64(s string) string {
	s = strings.TrimSpace(s)
	n := min(len(s), sniffBytes/3*4+64)
	prefix := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s[:n])
	if n < len(s) {
		prefix = prefix[:len(prefix)/4*4] // a whole number of quanta
	}
	data, err := decodeBase64(prefix)
	if err != nil {
		return fileUnknown
	}
	return sniff(data)
}

// filePart is what an image, file or audio part declares and carries.
type filePart struct {
	declared []string // claims: types, or "?<what>" for one the gateway does not know
	data     string   // base64 content; "" when none is inline
	remote   bool     // a url or file id: the gateway does not receive it
}

// fromDataURL fills the part from a data URL, or marks a url remote.
func (f *filePart) fromURL(u string) {
	if !strings.HasPrefix(u, "data:") {
		f.remote = u != ""
		return
	}
	f.fromFileData(u)
}

// fromFileData fills the part from file_data: plain base64 or a data URL.
func (f *filePart) fromFileData(s string) {
	if strings.HasPrefix(s, "data:") {
		comma := strings.IndexByte(s, ',')
		if comma < 0 {
			f.declared = append(f.declared, "?data url")
			return
		}
		meta := s[len("data:"):comma]
		if d := declaredMedia(strings.TrimSuffix(strings.ToLower(meta), ";base64")); d != "" {
			f.declared = append(f.declared, d)
		}
		s = s[comma+1:]
	}
	f.data = s
}

// claim adds a declaration when there is one.
func (f *filePart) claim(d string) {
	if d != "" {
		f.declared = append(f.declared, d)
	}
}

// describeFile reads what a part of the given type declares and carries,
// in the shapes of the three APIs.
func describeFile(kind string, p map[string]any) filePart {
	var f filePart
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	fileFields := func(m map[string]any) {
		if d := str(m, "file_data"); d != "" {
			f.fromFileData(d)
		} else if str(m, "file_id") != "" || str(m, "file_url") != "" {
			f.remote = true
		}
		f.claim(declaredExt(str(m, "filename")))
	}
	switch kind {
	case "image_url", "input_image": // chat completions, Responses
		switch u := p["image_url"].(type) {
		case string:
			f.fromURL(u)
		case map[string]any:
			f.fromURL(str(u, "url"))
		}
		if str(p, "file_id") != "" {
			f.remote = true
		}
	case "input_audio": // chat completions
		a, _ := p["input_audio"].(map[string]any)
		if a != nil {
			f.data = str(a, "data")
			f.claim(declaredExt("x." + str(a, "format")))
		}
	case "file": // chat completions
		if m, ok := p["file"].(map[string]any); ok {
			fileFields(m)
		}
	case "input_file": // Responses
		fileFields(p)
	case "image", "document": // Messages
		src, _ := p["source"].(map[string]any)
		switch str(src, "type") {
		case "base64":
			f.data = str(src, "data")
			mt := declaredMedia(str(src, "media_type"))
			if mt == "" {
				mt = "?no media type"
			}
			f.claim(mt)
		case "url", "file":
			f.remote = true
		}
	case "container_upload": // Messages: a file id
		f.remote = true
	}
	if f.data == "" && !f.remote {
		// A part the gateway finds nothing in: no content to check.
		f.remote = str(p, "file_id") != ""
	}
	return f
}

// detect returns the part's type, and the declaration its content
// contradicts ("" when none does).
func (f filePart) detect() (typ, mismatch string) {
	if f.remote {
		return fileRemote, ""
	}
	if f.data == "" {
		return fileUnknown, ""
	}
	typ = sniffBase64(f.data)
	for _, d := range f.declared {
		if d == typ || (strings.HasPrefix(d, "?") && typ == fileUnknown) {
			continue
		}
		if typ == "zip" && slices.Contains([]string{"docx", "xlsx", "pptx"}, d) {
			continue // an Office file whose part names come later in the zip
		}
		return typ, d
	}
	return typ, ""
}

// checkFile detects the type of an image, file or audio part, counts it,
// and applies the org's input settings to it. kind is the part's type.
func (g *textGuard) checkFile(kind string, p map[string]any) error {
	if unscannedKind(kind) == "other" {
		return nil // not an image, a file or audio: left to UNSCANNED_PARTS
	}
	typ, mismatch := describeFile(kind, p).detect()
	if !g.history {
		if g.files == nil {
			g.files = map[string]int{}
		}
		g.files[typ]++
		metrics.InputFiles.WithLabelValues(typ).Inc()
	}
	s := g.input
	switch {
	case s == nil:
		return nil
	case s.InputMode == indirect.InputTextOnly:
		return refuseFiles(kind, typ)
	case typ == fileRemote:
		return refuseRemote()
	case mismatch != "":
		return refuseMismatch(mismatch, typ)
	case !s.Allows(typ):
		return refuseType(typ, s.AllowedFileTypes)
	}
	return nil
}

// fileUnreadable handles an allowed file the gateway cannot read, for the
// given reason: with the org's unreadable_file_action block it refuses the
// request; otherwise the file is an unscanned part, as without settings
// (pdf: counted under input.pdf.reasons too).
func (g *textGuard) fileUnreadable(kind, reason string, pdf bool) error {
	if g.input != nil && g.input.UnreadableFileAction == indirect.UnreadableBlock {
		return refuseUnreadableFile(reason)
	}
	if pdf {
		g.pdfUnscanned(kind, reason)
	} else {
		g.noteUnscanned(kind)
	}
	if g.input != nil && !g.history {
		g.passed++
	}
	return nil
}

// unreadPart counts a part forwarded without being read, as before input
// settings. With them, a part that got this far holds an allowed file
// (checkFile) in a part type the gateway does not read (an image part
// carrying a PDF): an unreadable file.
func (g *textGuard) unreadPart(kind string) error {
	if g.input != nil && unscannedKind(kind) != "other" {
		return g.fileUnreadable(kind, "the gateway reads files only in file and document parts", false)
	}
	g.noteUnscanned(kind)
	return nil
}

// inputAudit is what the org's input settings did to a request.
type inputAudit struct {
	// Settings: the org has input settings; the tags are written only then.
	Settings bool
	Types    map[string]int // image, file and audio parts by detected type
	Refused  string         // the refusal's reason, refuse*
	Passed   int            // unreadable files forwarded under pass
}

// inputTags renders the audit tags: input:file_<type>=<n>,
// input:unreadable_passed=<n> and input:refused=<reason>, for an org with
// settings only, so that rows of the others are as before.
func inputTags(a inputAudit) []string {
	if !a.Settings {
		return nil
	}
	var tags []string
	for _, t := range fileTypesVar(a.Types) {
		tags = append(tags, fmt.Sprintf("input:file_%s=%d", t, a.Types[t]))
	}
	if a.Passed > 0 {
		tags = append(tags, fmt.Sprintf("input:unreadable_passed=%d", a.Passed))
	}
	if a.Refused != "" {
		tags = append(tags, "input:refused="+a.Refused)
	}
	return tags
}

// fileTypesVar is input.files.types: the detected types, sorted.
func fileTypesVar(types map[string]int) []string {
	out := make([]string, 0, len(types))
	for t, n := range types {
		if n > 0 {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// refuseInput answers a request the org's input settings refused, and
// records it.
func refuseInput(c *fiber.Ctx, entry *requestEntry, r *inputRefusal) error {
	slog.Info("refused by the org's input settings", "org", entry.OrgID, "reason", r.reason)
	metrics.InputRefused.WithLabelValues(r.reason).Inc()
	entry.Detected = layerInput
	entry.Input.Refused = r.reason
	entry.Scores.Injection.Label = "input_" + r.reason // the refusal's reason in the request log
	return c.Status(r.status).JSON(errorBody(r.message, "invalid_request_error", r.code))
}

// checkInputTokens applies the org's max_input_tokens to the text the
// request has to scan (the turns the gateway scans, tool descriptions
// included), before anything is scored.
func (gw gateway) checkInputTokens(g *textGuard) error {
	if g.input == nil || g.input.MaxInputTokens == nil {
		return nil
	}
	limit := *g.input.MaxInputTokens
	var texts []string
	for _, p := range g.parts {
		if !p.history {
			texts = append(texts, p.text)
		}
	}
	for _, t := range g.tools {
		texts = append(texts, t.Description)
	}
	ok, err := gw.withinTokens(texts, limit)
	if err != nil {
		return err
	}
	if !ok {
		return refuseTokens(limit)
	}
	return nil
}

// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/pdftext"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/testpdf"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/guard-spec/guard-spec/internal/metrics"
)

// withInput gives every org the input settings s (nil: none).
func withInput(s *indirect.InputSettings) func(*gateway) {
	return func(gw *gateway) {
		gw.settings = func(context.Context, uuid.UUID) (indirect.Settings, error) {
			return indirect.Settings{Input: s}, nil
		}
	}
}

func hybridPDF(action string) *indirect.InputSettings {
	return &indirect.InputSettings{InputMode: indirect.InputHybrid, AllowedFileTypes: []string{"pdf"}, UnreadableFileAction: action}
}

var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

// hasCode reports the error code in a refusal; the Anthropic error shape
// carries none, only its type.
func hasCode(anthropic bool, body, code string) bool {
	if anthropic {
		return strings.Contains(body, `"type":"error"`)
	}
	return strings.Contains(body, code)
}

func TestSniffFileTypes(t *testing.T) {
	for want, data := range map[string][]byte{
		"pdf": []byte("%PDF-1.7\n"), "png": pngBytes, "jpeg": {0xFF, 0xD8, 0xFF, 0xE0}, "gif": []byte("GIF89a.."),
		"webp": []byte("RIFF\x00\x00\x00\x00WEBPVP8 "), "wav": []byte("RIFF\x00\x00\x00\x00WAVEfmt "),
		"ogg": []byte("OggS\x00"), "flac": []byte("fLaC\x00"), "mp3": []byte("ID3\x04"),
		"docx": []byte("PK\x03\x04....[Content_Types].xml....word/document.xml"),
		"xlsx": []byte("PK\x03\x04....xl/workbook.xml"), "pptx": []byte("PK\x03\x04....ppt/slides"),
		"zip": []byte("PK\x03\x04....readme.txt"), "unknown": []byte("hello world"),
	} {
		if got := sniff(data); got != want {
			t.Errorf("sniff(%q) = %s, want %s", data, got, want)
		}
		if got := sniffBase64(b64(data)); got != want {
			t.Errorf("sniffBase64(%s) = %s, want %s", want, got, want)
		}
	}
	// A long file is read from its start only; wrapped base64 too.
	long := append([]byte("%PDF-1.4\n"), make([]byte, 100_000)...)
	enc := b64(long)
	if sniffBase64(enc) != "pdf" || sniffBase64(enc[:76]+"\n"+enc[76:]) != "pdf" {
		t.Error("long or wrapped PDF")
	}
	if sniffBase64("!!not base64") != fileUnknown {
		t.Error("invalid base64")
	}
}

func TestDescribeFile(t *testing.T) {
	pdf, png := b64([]byte("%PDF-1.7\n")), b64(pngBytes)
	for _, tc := range []struct {
		kind, part         string
		typ, mismatchClaim string
	}{
		{"file", `{"file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,` + pdf + `"}}`, "pdf", ""},
		{"file", `{"file":{"filename":"a.pdf","file_data":"` + png + `"}}`, "png", "pdf"},          // extension lies
		{"file", `{"file":{"file_data":"data:application/pdf;base64,` + png + `"}}`, "png", "pdf"}, // media type lies
		{"file", `{"file":{"filename":"notes.txt","file_data":"` + pdf + `"}}`, "pdf", "?txt"},     // unknown claim, known content
		{"file", `{"file":{"filename":"notes.txt","file_data":"` + b64([]byte("hi")) + `"}}`, "unknown", ""},
		{"file", `{"file":{"file_id":"file_1"}}`, "remote", ""},
		{"image_url", `{"image_url":{"url":"data:image/png;base64,` + png + `"}}`, "png", ""},
		{"image_url", `{"image_url":{"url":"https://img.example/a.png"}}`, "remote", ""},
		{"input_image", `{"image_url":"data:image/jpeg;base64,` + png + `"}`, "png", "jpeg"},
		{"input_audio", `{"input_audio":{"data":"` + b64([]byte("RIFF\x00\x00\x00\x00WAVE")) + `","format":"wav"}}`, "wav", ""},
		{"input_file", `{"filename":"a.pdf","file_data":"` + pdf + `"}`, "pdf", ""},
		{"input_file", `{"file_url":"https://files.example/a.pdf"}`, "remote", ""},
		{"document", `{"source":{"type":"base64","media_type":"application/pdf","data":"` + pdf + `"}}`, "pdf", ""},
		{"document", `{"source":{"type":"base64","data":"` + pdf + `"}}`, "pdf", "?no media type"},
		{"document", `{"source":{"type":"url","url":"https://files.example/a.pdf"}}`, "remote", ""},
		{"image", `{"source":{"type":"base64","media_type":"image/png","data":"` + png + `"}}`, "png", ""},
		{"container_upload", `{"file_id":"f"}`, "remote", ""},
		{"file", `{}`, "unknown", ""},
	} {
		var p map[string]any
		if err := json.Unmarshal([]byte(tc.part), &p); err != nil {
			t.Fatal(err)
		}
		typ, mismatch := describeFile(tc.kind, p).detect()
		if typ != tc.typ || mismatch != tc.mismatchClaim {
			t.Errorf("%s %s: %s %q, want %s %q", tc.kind, tc.part[:min(len(tc.part), 60)], typ, mismatch, tc.typ, tc.mismatchClaim)
		}
	}
}

// Owner decision 1: an org without input settings is served exactly as by
// 0.6.0 (PDF_EXTRACT, UNSCANNED_PARTS, MAX_SCAN_TOKENS alone): the same
// status, upstream call, audit tags and policy fields as without a settings
// loader, for images, readable, unreadable and remote PDFs, under each
// UNSCANNED_PARTS mode and with PDF_EXTRACT on and off.
func TestInputInheritIsV060(t *testing.T) {
	lim := pdftext.DefaultLimits()
	type result struct {
		status, hits int
		tags         []string
		unscanned    map[string]int
		pdf          pdfCounts
	}
	run := func(t *testing.T, api pdfAPI, part string, extract bool, mode string, loader bool) result {
		var l *pdftext.Limits
		if extract {
			l = &lim
		}
		var mutate func(*gateway)
		if loader {
			mutate = withInput(nil)
		}
		h, up := pdfGateway(t, api, l, indirect.ActionBlock, mode, mutate)
		resp, _ := h.post(t, api.path, api.body(part), nil)
		row := h.oneRow(t)
		return result{resp.StatusCode, int(up.hits.Load()), auditTags(row), row.Unscanned, row.PDF}
	}
	images := map[string]string{
		"chat":      `{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}}`,
		"messages":  `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}`,
		"responses": `{"type":"input_image","image_url":"` + tinyPNG + `"}`,
	}
	for _, api := range pdfAPIs() {
		parts := map[string]string{"image": images[api.name], "pdf": api.inline(testpdf.Simple(pdfBenign)), "remote": api.remote,
			"no_text": api.inline(pdfUnreadable()[pdftext.ReasonNoText])}
		for name, part := range parts {
			for _, extract := range []bool{true, false} {
				for _, mode := range []string{indirect.UnscannedAllow, indirect.UnscannedLog, indirect.UnscannedBlock} {
					t.Run(api.name+"/"+name+"/"+mode, func(t *testing.T) {
						before := run(t, api, part, extract, mode, false)
						after := run(t, api, part, extract, mode, true)
						if before.status != after.status || before.hits != after.hits || !slices.Equal(before.tags, after.tags) ||
							!maps.Equal(before.unscanned, after.unscanned) || !maps.Equal(before.pdf.Unscanned, after.pdf.Unscanned) ||
							before.pdf.Scanned != after.pdf.Scanned {
							t.Errorf("extract %v: without settings %+v, inherited %+v", extract, before, after)
						}
						for _, tag := range after.tags {
							if strings.HasPrefix(tag, "input:file_") || strings.HasPrefix(tag, "input:refused") {
								t.Errorf("new tag %s on an org without settings", tag)
							}
						}
					})
				}
			}
		}
	}
}

// MAX_SCAN_TOKENS alone still decides for an org without settings.
func TestInputInheritKeepsTokenCap(t *testing.T) {
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, func(gw *gateway) {
		cfg := defaultScanConfig()
		cfg.MaxScanTokens, cfg.ScanTokens = 5, 5
		gw.scan = &cfg
		withInput(nil)(gw)
	})
	resp, got := h.post(t, "/v1/chat/completions", chatBody(messages("user", strings.Repeat("word ", 50)), ""), nil)
	if resp.StatusCode != 413 || strings.Contains(got, "max_input_tokens") {
		t.Errorf("got %d %s", resp.StatusCode, got)
	}
}

// text_only refuses images, files and audio on every API with 415 and a
// JSON error telling the app to send text; a text request passes.
func TestInputTextOnly(t *testing.T) {
	textOnly := &indirect.InputSettings{InputMode: indirect.InputTextOnly, AllowedFileTypes: []string{},
		UnreadableFileAction: indirect.UnreadableBlock}
	for _, api := range unscannedAPIs() {
		t.Run(api.name, func(t *testing.T) {
			up := newFakeUpstream(t, api.upstream)
			upURL := up.URL
			if api.anthropic {
				upURL = ""
			}
			h := startGateway(t, upURL, func(gw *gateway) {
				if api.anthropic {
					withAnthropic(up.URL)(gw)
				}
				withInput(textOnly)(gw)
			})
			before := testutil.ToFloat64(metrics.InputRefused.WithLabelValues(refuseTextOnly))
			resp, got := h.post(t, api.path, api.body, nil)
			row := h.oneRow(t)
			if resp.StatusCode != 415 || up.hits.Load() != 0 || !hasCode(api.anthropic, got, "files_not_accepted") ||
				!strings.Contains(got, "send the text instead") {
				t.Errorf("got %d %s, upstream hits %d", resp.StatusCode, got, up.hits.Load())
			}
			if row.Action != actionBlock || row.Detected != layerInput || !slices.Contains(auditTags(row), "input:refused=text_only") {
				t.Errorf("row %s %s tags %v", row.Action, row.Detected, auditTags(row))
			}
			if testutil.ToFloat64(metrics.InputRefused.WithLabelValues(refuseTextOnly)) != before+1 {
				t.Error("refusal not counted")
			}
		})
	}
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, withInput(textOnly))
	if resp, got := h.post(t, "/v1/chat/completions", chatBody(messages("user", "Hello"), ""), nil); resp.StatusCode != 200 {
		t.Errorf("text request: %d %s", resp.StatusCode, got)
	}
}

// hybrid with pdf: an inline PDF is read and scanned; an image, a remote
// file and a file whose content contradicts its declaration are refused.
func TestInputHybrid(t *testing.T) {
	lim := pdftext.DefaultLimits()
	images := map[string]string{
		"chat":      `{"type":"image_url","image_url":{"url":"` + tinyPNG + `"}}`,
		"messages":  `{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}`,
		"responses": `{"type":"input_image","image_url":"` + tinyPNG + `"}`,
	}
	fakes := map[string]string{ // declared pdf, PNG content
		"chat":      `{"type":"file","file":{"filename":"a.pdf","file_data":"data:application/pdf;base64,` + b64(pngBytes) + `"}}`,
		"messages":  `{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"` + b64(pngBytes) + `"}}`,
		"responses": `{"type":"input_file","filename":"a.pdf","file_data":"` + b64(pngBytes) + `"}`,
	}
	for _, api := range pdfAPIs() {
		for _, tc := range []struct {
			name, part string
			status     int
			code       string
			reason     string
		}{
			{"pdf", api.inline(testpdf.Simple(pdfBenign)), 200, "", ""},
			{"image", images[api.name], 415, "file_type_not_allowed", refuseTypeNotAllowed},
			{"remote", api.remote, 415, "file_not_inline", refuseNotInline},
			{"mismatch", fakes[api.name], 415, "file_type_mismatch", refuseTypeMismatch},
		} {
			t.Run(api.name+"/"+tc.name, func(t *testing.T) {
				h, up := pdfGateway(t, api, &lim, indirect.ActionBlock, indirect.UnscannedLog, withInput(hybridPDF(indirect.UnreadableBlock)))
				resp, got := h.post(t, api.path, api.body(tc.part), nil)
				row := h.oneRow(t)
				tags := auditTags(row)
				if resp.StatusCode != tc.status || (tc.code != "" && !hasCode(api.anthropic, got, tc.code)) {
					t.Fatalf("got %d %s", resp.StatusCode, got)
				}
				if tc.status == 200 {
					if up.hits.Load() != 1 || row.PDF.Scanned != 1 || !slices.Equal(tags, []string{"input:pdf_scanned=1", "input:file_pdf=1"}) {
						t.Errorf("hits %d pdf %+v tags %v", up.hits.Load(), row.PDF, tags)
					}
					return
				}
				if up.hits.Load() != 0 || row.Detected != layerInput || !slices.Contains(tags, "input:refused="+tc.reason) {
					t.Errorf("hits %d detected %s tags %v", up.hits.Load(), row.Detected, tags)
				}
			})
		}
	}
}

// An allowed file the gateway cannot read: refused (422) under block,
// forwarded unscanned and tagged under pass, which UNSCANNED_PARTS=block
// still refuses. PDF_EXTRACT=off makes every PDF unreadable.
func TestInputUnreadable(t *testing.T) {
	lim := pdftext.DefaultLimits()
	for _, api := range pdfAPIs() {
		for reason, pdf := range pdfUnreadable() {
			part := api.inline(pdf)
			t.Run(api.name+"/"+reason+"/block", func(t *testing.T) {
				h, up := pdfGateway(t, api, &lim, indirect.ActionBlock, indirect.UnscannedLog, withInput(hybridPDF(indirect.UnreadableBlock)))
				resp, got := h.post(t, api.path, api.body(part), nil)
				row := h.oneRow(t)
				if resp.StatusCode != 422 || up.hits.Load() != 0 || !hasCode(api.anthropic, got, "file_unreadable") || !strings.Contains(got, reason) {
					t.Errorf("got %d %s", resp.StatusCode, got)
				}
				if !slices.Contains(auditTags(row), "input:refused=unreadable") {
					t.Errorf("tags %v", auditTags(row))
				}
			})
			t.Run(api.name+"/"+reason+"/pass", func(t *testing.T) {
				// pass tags the row even where UNSCANNED_PARTS=allow is quiet.
				h, up := pdfGateway(t, api, &lim, indirect.ActionBlock, indirect.UnscannedAllow, withInput(hybridPDF(indirect.UnreadablePass)))
				resp, got := h.post(t, api.path, api.body(part), nil)
				row := h.oneRow(t)
				want := []string{"input:unscanned_file=1", "input:pdf_unscanned_" + reason + "=1", "input:file_pdf=1", "input:unreadable_passed=1"}
				if resp.StatusCode != 200 || up.hits.Load() != 1 || !strings.Contains(sentBody(up), b64(pdf)) {
					t.Fatalf("got %d %s", resp.StatusCode, got)
				}
				if tags := auditTags(row); !slices.Equal(tags, want) {
					t.Errorf("tags %v, want %v", tags, want)
				}
			})
		}
		t.Run(api.name+"/pass under UNSCANNED_PARTS=block", func(t *testing.T) {
			h, up := pdfGateway(t, api, &lim, indirect.ActionBlock, indirect.UnscannedBlock, withInput(hybridPDF(indirect.UnreadablePass)))
			resp, got := h.post(t, api.path, api.body(api.inline(pdfUnreadable()[pdftext.ReasonNoText])), nil)
			if resp.StatusCode != 400 || up.hits.Load() != 0 || !hasCode(api.anthropic, got, "unscanned_content") {
				t.Errorf("got %d %s", resp.StatusCode, got)
			}
		})
		for _, action := range []string{indirect.UnreadableBlock, indirect.UnreadablePass} {
			t.Run(api.name+"/extract off/"+action, func(t *testing.T) {
				h, up := pdfGateway(t, api, nil, indirect.ActionBlock, indirect.UnscannedLog, withInput(hybridPDF(action)))
				resp, got := h.post(t, api.path, api.body(api.inline(testpdf.Simple(pdfBenign))), nil)
				want, hits := 422, int32(0)
				if action == indirect.UnreadablePass {
					want, hits = 200, 1
				}
				if resp.StatusCode != want || up.hits.Load() != hits {
					t.Errorf("got %d %s, hits %d", resp.StatusCode, got, up.hits.Load())
				}
			})
		}
	}
}

// max_input_tokens refuses a request with more tokens before it is scored.
func TestInputMaxTokens(t *testing.T) {
	n := 10
	s := &indirect.InputSettings{InputMode: indirect.InputTextOnly, MaxInputTokens: &n, AllowedFileTypes: []string{},
		UnreadableFileAction: indirect.UnreadableBlock}
	up := newFakeUpstream(t, okUpstream)
	h := startGateway(t, up.URL, withInput(s))
	resp, got := h.post(t, "/v1/chat/completions", chatBody(messages("user", strings.Repeat("word ", 50)), ""), nil)
	row := h.oneRow(t)
	if resp.StatusCode != 413 || up.hits.Load() != 0 || !strings.Contains(got, "max_input_tokens_exceeded") {
		t.Errorf("over: %d %s", resp.StatusCode, got)
	}
	if !slices.Contains(auditTags(row), "input:refused=max_input_tokens") || row.Scores.Injection.Confidence != 0 {
		t.Errorf("row tags %v scores %+v", auditTags(row), row.Scores)
	}
	if resp, got = h.post(t, "/v1/chat/completions", chatBody(messages("user", "short one"), ""), nil); resp.StatusCode != 200 {
		t.Errorf("under: %d %s", resp.StatusCode, got)
	}
}

// input.files.types reaches policies, with or without input settings.
func TestInputFileTypesPolicyField(t *testing.T) {
	api := unscannedAPIs()[0]
	r := rule(policy.ActionBlock, "input.files.types", "contains", "png")
	up := newFakeUpstream(t, api.upstream)
	h := startGateway(t, up.URL, withRules(r))
	resp, got := h.post(t, api.path, api.body, nil)
	row := h.oneRow(t)
	if resp.StatusCode != 400 || up.hits.Load() != 0 || row.Detected != layerPolicy {
		t.Errorf("got %d %s, detected %s", resp.StatusCode, got, row.Detected)
	}
	if vars := policyVars(row, nil, 0); !slices.Equal(vars.FileTypes, []string{"png"}) {
		t.Errorf("input.files.types = %v", vars.FileTypes)
	}
}

// /readyz reports the input limits the control plane checks against.
func TestReadyzInputLimits(t *testing.T) {
	h := startGateway(t, "", func(gw *gateway) {
		cfg := defaultScanConfig()
		cfg.MaxScanTokens, cfg.Unscanned = 200000, indirect.UnscannedBlock
		gw.scan = &cfg
	})
	resp, err := http.Get(h.url + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Input map[string]any `json:"input"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	in := out.Input
	if in["max_scan_tokens"] != float64(200000) || in["max_input_tokens_ceiling"] != float64(200000) || in["pdf_extract"] != false ||
		in["unscanned_parts"] != "block" {
		t.Errorf("input = %v", in)
	}
}

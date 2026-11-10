// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/pdftext"
)

// PDF text extraction (RF-8e6d0a82). A PDF sent inline (a document block
// with a base64 source on /v1/messages, a file part with file_data on chat
// completions, an input_file item with file_data on /v1/responses) used to
// be an unscanned part: forwarded unread and counted under UNSCANNED_PARTS.
// With PDF_EXTRACT=on (the default) the gateway extracts its text with
// internal/pdftext (every text object, hidden or not, annotations and form
// fields) and scores it as a document: the same path as a text document, so
// INDIRECT_ACTION, MAX_SCAN_TOKENS and the scan cache apply, and with
// INDIRECT_ACTION=redact the part is replaced by the document placeholder.
// The forwarded body is otherwise byte-identical: the PDF itself is never
// rewritten.
//
// A PDF whose text cannot be extracted (no text layer, encrypted, damaged,
// timed out, over a limit, an extractor fault) and a PDF the gateway cannot
// fetch (a url, file_id or file_url source: reason remote) stay unscanned
// parts, as before, and the reason is recorded: input.pdf.* for policies,
// input:pdf_* audit tags and the pdf_extract metrics. PDF_EXTRACT=off is
// exactly the behaviour before this feature.

const (
	pdfReasonRemote       = "remote"
	pdfExtractResultBusy  = "busy" // metric result: no extractor within LARGE_SCAN_QUEUE_TIMEOUT
	pdfExtractCacheBytes  = 32 << 20
	pdfExtractCacheMaxLen = 256
)

// pdfExtractor extracts the text of PDF parts for the guard, with the shared
// pdftext runtime. Its slots bound the documents parsed at once: a request
// waits for one for up to queueTimeout (LARGE_SCAN_QUEUE_TIMEOUT) and is then
// refused with 429, as the large-input lane refuses a request it cannot take.
type pdfExtractor struct {
	ctx          context.Context // the gateway's base context
	limits       pdftext.Limits
	queueTimeout time.Duration
	slots        chan struct{}

	// cache keeps the outcome of recent documents by content hash, so that a
	// session that resends a PDF in every turn (SCAN_HISTORY=latest) parses
	// it once; the text then goes through the scan cache like any document.
	mu    sync.Mutex
	cache map[[32]byte]pdftext.Result
	order [][32]byte
	bytes int
}

// newPDFExtractor returns the extractor of the gateway's configuration.
func newPDFExtractor(ctx context.Context, lim pdftext.Limits, queueTimeout time.Duration) *pdfExtractor {
	if lim.MaxConcurrency <= 0 {
		lim.MaxConcurrency = pdftext.DefaultLimits().MaxConcurrency
	}
	if queueTimeout <= 0 {
		queueTimeout = defaultLargeQueueTimeout
	}
	return &pdfExtractor{ctx: ctx, limits: lim, queueTimeout: queueTimeout,
		slots: make(chan struct{}, lim.MaxConcurrency), cache: map[[32]byte]pdftext.Result{}}
}

// warm compiles the PDFium module in the background, so that the first
// request does not pay for it. Readiness never waits for it.
func (p *pdfExtractor) warm() {
	go func() {
		start := time.Now()
		if err := pdftext.WarmWith(p.ctx, p.limits); err != nil {
			slog.Warn("pdf extractor warm-up failed; the first PDF will start it", "err", err)
			return
		}
		slog.Info("pdf extractor ready", "took", time.Since(start).Round(time.Millisecond),
			"max_bytes", p.limits.MaxBytes, "max_pages", p.limits.MaxPages, "max_text_bytes", p.limits.MaxTextBytes,
			"timeout", p.limits.Timeout, "memory", p.limits.MemoryBytes, "concurrency", p.limits.MaxConcurrency)
	}()
}

// retryAfter is the Retry-After of a 429 from the extractor, in seconds.
func (p *pdfExtractor) retryAfter() int { return max(1, int(math.Ceil(p.queueTimeout.Seconds()))) }

// extract returns the text of data, or the reason it has none. The error is
// errScanBusy when no slot was free within queueTimeout; everything else is
// reported in the result's Reason.
func (p *pdfExtractor) extract(data []byte) (pdftext.Result, error) {
	if int64(len(data)) > p.limits.MaxBytes {
		metrics.PDFExtract.WithLabelValues(pdftext.ReasonOverLimit).Inc()
		return pdftext.Result{Reason: pdftext.ReasonOverLimit}, nil
	}
	key := sha256.Sum256(data)
	if res, ok := p.cached(key); ok {
		metrics.PDFExtract.WithLabelValues(res.Reason).Inc()
		return res, nil
	}
	timer := time.NewTimer(p.queueTimeout)
	defer timer.Stop()
	select {
	case p.slots <- struct{}{}:
	case <-timer.C:
		metrics.PDFExtract.WithLabelValues(pdfExtractResultBusy).Inc()
		return pdftext.Result{}, scanBusy{after: p.retryAfter()}
	case <-p.ctx.Done():
		return pdftext.Result{}, p.ctx.Err()
	}
	start := time.Now()
	res, err := pdftext.Extract(p.ctx, data, p.limits)
	<-p.slots
	metrics.PDFExtractSeconds.Observe(time.Since(start).Seconds())
	if err != nil && res.Reason == "" {
		res.Reason = pdftext.ReasonInternal
	}
	if res.Reason == pdftext.ReasonInternal {
		slog.Warn("pdf extraction failed", "err", err)
	}
	if res.Reason == pdftext.ReasonOK {
		metrics.PDFTextBytes.Observe(float64(len(res.Text)))
	}
	metrics.PDFExtract.WithLabelValues(res.Reason).Inc()
	p.remember(key, res)
	return res, nil
}

func (p *pdfExtractor) cached(key [32]byte) (pdftext.Result, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	res, ok := p.cache[key]
	return res, ok
}

// remember keeps an outcome that does not depend on the moment: a timeout
// or an internal fault may not happen again.
func (p *pdfExtractor) remember(key [32]byte, res pdftext.Result) {
	switch res.Reason {
	case pdftext.ReasonTimeout, pdftext.ReasonInternal:
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.cache[key]; ok {
		return
	}
	p.cache[key] = res
	p.order = append(p.order, key)
	p.bytes += len(res.Text)
	for len(p.order) > pdfExtractCacheMaxLen || p.bytes > pdfExtractCacheBytes {
		oldest := p.order[0]
		p.order = p.order[1:]
		p.bytes -= len(p.cache[oldest].Text)
		delete(p.cache, oldest)
	}
}

// pdfCounts records the PDF parts of a request: how many were scanned and,
// by reason, how many were not. Like the unscanned counts, it covers the
// turns the gateway scans.
type pdfCounts struct {
	Scanned   int
	Unscanned map[string]int
}

func (c *pdfCounts) noteUnscanned(reason string) {
	if c.Unscanned == nil {
		c.Unscanned = map[string]int{}
	}
	c.Unscanned[reason]++
}

// empty reports no PDF part at all.
func (c pdfCounts) empty() bool { return c.Scanned == 0 && len(c.Unscanned) == 0 }

// pdfTags renders the counts for the audit row: "input:pdf_scanned=<n>" and
// "input:pdf_unscanned_<reason>=<n>". The unscanned tags are left out when
// quiet (UNSCANNED_PARTS=allow), like the input:unscanned_* tags.
func pdfTags(c pdfCounts, quiet bool) []string {
	var tags []string
	if c.Scanned > 0 {
		tags = append(tags, fmt.Sprintf("input:pdf_scanned=%d", c.Scanned))
	}
	if quiet {
		return tags
	}
	for _, r := range indirect.PDFReasons {
		if n := c.Unscanned[r]; n > 0 {
			tags = append(tags, fmt.Sprintf("input:pdf_unscanned_%s=%d", r, n))
		}
	}
	return tags
}

// pdfMagic starts every PDF file.
const pdfMagic = "%PDF-"

// isPDFBytes reports whether data looks like a PDF file.
func isPDFBytes(data []byte) bool {
	return len(data) >= len(pdfMagic) && string(data[:len(pdfMagic)]) == pdfMagic
}

// decodeFileData decodes the file_data of a chat file part or a Responses
// input_file item: plain base64, or a data URL. It reports whether the data
// is a PDF (the URL says application/pdf, or the bytes start with %PDF-).
// ok is false when the string is not valid base64.
func decodeFileData(s string) (data []byte, pdf, ok bool) {
	declared := false
	if strings.HasPrefix(s, "data:") {
		comma := strings.IndexByte(s, ',')
		if comma < 0 {
			return nil, false, false
		}
		meta := strings.ToLower(s[len("data:"):comma])
		if !strings.HasSuffix(meta, ";base64") {
			return nil, false, false
		}
		mediaType := strings.TrimSpace(strings.SplitN(strings.TrimSuffix(meta, ";base64"), ";", 2)[0])
		declared = mediaType == "application/pdf"
		s = s[comma+1:]
	}
	data, err := decodeBase64(s)
	if err != nil {
		return nil, false, false
	}
	return data, declared || isPDFBytes(data), true
}

// decodeBase64 accepts standard base64 with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// base64Len bounds the decoded size of a base64 string without decoding it.
func base64Len(s string) int64 { return int64(len(s)) / 4 * 3 }

// guardPDF scores the text of a PDF part as a document, in the current
// source and redactor (set by the caller with g.as). kind is the part's type
// for the unscanned count when the text cannot be used. data is the file;
// nil with remote set means the part refers to a file the gateway cannot
// fetch (a url or file id).
//
// A PDF that yields no usable text is an unscanned part as before, with the
// reason recorded. In an earlier turn (g.history) the text is still scored,
// through the scan cache like a text document, but nothing is counted.
func (g *textGuard) guardPDF(kind string, data []byte, remote bool) error {
	if remote {
		metrics.PDFExtract.WithLabelValues(pdfReasonRemote).Inc()
		g.pdfUnscanned(kind, pdfReasonRemote)
		return nil
	}
	res, err := g.pdf.extract(data)
	if err != nil {
		return err
	}
	if res.Reason == pdftext.ReasonOK && !g.limits.long && len(res.Text) > maxUntrustedBytes {
		// More than the short path scans in one request and no long path
		// (MAX_SCAN_TOKENS unset): unscanned rather than 413, the PDF was
		// not readable before either.
		res.Reason = pdftext.ReasonOverLimit
	}
	if res.Reason != pdftext.ReasonOK {
		g.pdfUnscanned(kind, res.Reason)
		return nil
	}
	if !g.history {
		g.pdfs.Scanned++
	}
	return g.scoreUntrusted(res.Text)
}

// pdfUnscanned counts a PDF part the gateway forwards without reading it.
func (g *textGuard) pdfUnscanned(kind, reason string) {
	g.noteUnscanned(kind)
	if g.history {
		return
	}
	g.pdfs.noteUnscanned(reason)
}

// guardFilePart handles a chat file part ({"type":"file","file":{...}}) or a
// Responses input_file item, whose fields are file_data (inline, base64 or a
// data URL), file_id or file_url. redact replaces the part with the document
// placeholder. A part that is not a PDF the gateway can read is an unscanned
// part, as before.
func (g *textGuard) guardFilePart(kind string, file map[string]any, redact func()) error {
	if g.pdf == nil || file == nil {
		g.noteUnscanned(kind)
		return nil
	}
	if err := rejectShadowKeys(file, "file_data", "file_id", "file_url"); err != nil {
		return err
	}
	return g.as(indirect.SourceDocument, redact, func() error {
		if raw, ok := file["file_data"].(string); ok && raw != "" {
			if base64Len(raw) > g.pdf.limits.MaxBytes {
				g.pdfUnscanned(kind, pdftext.ReasonOverLimit)
				metrics.PDFExtract.WithLabelValues(pdftext.ReasonOverLimit).Inc()
				return nil
			}
			data, pdf, ok := decodeFileData(raw)
			if !ok || !pdf {
				g.noteUnscanned(kind) // not a PDF, or not readable as one
				return nil
			}
			return g.guardPDF(kind, data, false)
		}
		for _, key := range []string{"file_id", "file_url"} {
			if s, ok := file[key].(string); ok && s != "" {
				return g.guardPDF(kind, nil, true)
			}
		}
		g.noteUnscanned(kind)
		return nil
	})
}

// replaceWithText turns a content part into a text part of the given type
// carrying the document placeholder, in place.
func replaceWithText(part map[string]any, textType string) {
	for k := range part {
		delete(part, k)
	}
	part["type"], part["text"] = textType, redactedDocument
}

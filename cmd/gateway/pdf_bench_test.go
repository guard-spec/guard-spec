// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/pdftext"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
	"github.com/guard-spec/guard-spec/internal/testpdf"
)

// End-to-end cost of a long PDF (RF-8e6d0a82): a generated 100-page PDF of
// about 200k tokens of benign text goes through the gateway to a fake
// upstream on each API shape, with MAX_SCAN_TOKENS=250000 and
// INDIRECT_ACTION=redact (so that every window is scored: block stops at the
// first window over the threshold). The numbers go in docs/sizing.md.
//
//	go test ./cmd/gateway -run '^$' -bench 'PDFDocument$' -benchtime 3x       # L1 only
//	make onnx-deps && CGO_ENABLED=1 CGO_LDFLAGS=-L$PWD/.onnx/lib ONNXRUNTIME_LIB=$PWD/.onnx/lib/libonnxruntime.dylib \
//	  go test -tags onnx ./cmd/gateway -run '^$' -bench 'PDFDocumentML' -benchtime 3x   # with the models
//
// Reported per operation: extract_ms (the extractor, from the
// pdf_extract_seconds histogram), scan_ms (the whole request, response
// included), windows (scored + duplicate; skipped must be 0: every window
// was scored), tokens and pages of the document, redacted (1 when the
// classifier took the benign document for an injection), and over the
// sub-benchmark rss_peak_delta_MB (peak resident set, before and after) and
// heap_sys_delta_MB (Go heap, wazero's linear memory included). cold_start
// measures a fresh PDFium runtime: compile_ms (the WebAssembly module) and
// first_extract_ms (the first document through it).

const (
	pdfBenchPages     = 100
	pdfBenchLinesPage = 80 // about 8 KB of text per page: 800 KB, about 200k tokens
	pdfBenchMaxTokens = 250_000
)

// pdfBenchDocument is the benchmark's PDF: pages of numbered benign lines,
// compressed as a real document would be. copy makes the text distinct per
// iteration so that neither the extractor's cache nor a scan cache answers
// instead of a scan.
func pdfBenchDocument(copy int) []byte {
	pages := make([]testpdf.Page, 0, pdfBenchPages)
	for p := range pdfBenchPages {
		lines := make([]string, 0, pdfBenchLinesPage)
		for i := range pdfBenchLinesPage {
			lines = append(lines, fmt.Sprintf("Copy %d page %d line %02d: the quarterly report shows steady growth in region %d, "+
				"costs in line with the plan.", copy, p+1, i, (p*7+i)%17))
		}
		pages = append(pages, testpdf.Page{Content: testpdf.Paragraphs(lines, 8), Compress: true})
	}
	return testpdf.Build(testpdf.Document{Pages: pages})
}

// pdfBenchLimits are the extractor limits of a gateway with
// MAX_SCAN_TOKENS=250000 and the PDF_EXTRACT defaults.
func pdfBenchLimits(b *testing.B) pdftext.Limits {
	b.Helper()
	cfg, err := loadPDFConfig(func(string) string { return "" }, pdfBenchMaxTokens)
	if err != nil {
		b.Fatal(err)
	}
	return cfg.Limits
}

// histogramStats reads a histogram's sample count and sum.
func histogramStats(h prometheus.Histogram) (uint64, float64) {
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		panic(err)
	}
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

// pdfBenchPost sends body to the gateway and returns the status.
func pdfBenchPost(b *testing.B, client *http.Client, url, body string) int {
	b.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test")
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		b.Fatal(err)
	}
	return resp.StatusCode
}

// runPDFBench runs the benchmark for one API shape with the given runner.
func runPDFBench(b *testing.B, api pdfAPI, runner *inference.Runner) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	b.Cleanup(func() { slog.SetDefault(prev) })
	lim := pdfBenchLimits(b)
	if err := pdftext.WarmWith(context.Background(), lim); err != nil {
		b.Fatal(err)
	}
	up := newFakeUpstream(b, api.upstream)
	upURL := up.URL
	if api.anthropic {
		upURL = ""
	}
	h := startGateway(b, upURL, func(gw *gateway) {
		if api.anthropic {
			withAnthropic(up.URL)(gw)
		}
		cfg := defaultScanConfig()
		cfg.MaxScanTokens, cfg.ScanTokens = pdfBenchMaxTokens, pdfBenchMaxTokens
		cfg.IndirectAction = indirect.ActionRedact
		gw.scan = &cfg
		gw.large = largeLaneFor(pdfBenchMaxTokens, laneConfig(defaultLargeConcurrency()))
		gw.pdf = newPDFExtractor(context.Background(), lim, 30*time.Second)
		gw.runner = runner
	})
	client := &http.Client{Timeout: 10 * time.Minute}

	// The document's size and the windows the gateway will score: the
	// extracted text, sanitized as the guard sanitizes it, through the long
	// path with no threshold.
	sample := pdfBenchDocument(0)
	res, err := pdftext.Extract(context.Background(), sample, lim)
	if err != nil || res.Reason != pdftext.ReasonOK {
		b.Fatalf("extract: %v, reason %s, %d pages, %d bytes of text", err, res.Reason, res.Pages, len(res.Text))
	}
	cleaned, _, err := sanitizer.Sanitize(res.Text)
	if err != nil {
		b.Fatal(err)
	}
	tokens, err := runner.CountTokens(cleaned)
	if err != nil {
		b.Fatal(err)
	}
	ls := inference.NewLongScan(inference.LongOptions{Limiter: h.gw.large.lim})
	ctx := onnx.WithLimiter(inference.WithLongScan(context.Background(), ls), h.gw.large.lim)
	if err := runner.Prescore(ctx, ls, []inference.LongInput{{Text: cleaned}}); err != nil {
		b.Fatal(err)
	}
	wantWindows := ls.Stats().Windows

	docs := make([]string, b.N)
	for i := range docs {
		docs[i] = api.body(api.inline(pdfBenchDocument(i + 1)))
	}
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	heapBefore, rssBefore := ms.HeapSys, maxRSS()
	extractN, extractSum := histogramStats(metrics.PDFExtractSeconds)
	scored, dup, skipped := windows("scored"), windows("duplicate"), windows("skipped")
	var redacted, scanned, first time.Duration
	b.ResetTimer()
	for i := range b.N {
		up.mu.Lock()
		up.body = ""
		up.mu.Unlock()
		start := time.Now()
		status := pdfBenchPost(b, client, h.url+api.path, docs[i])
		took := time.Since(start)
		scanned += took
		if i == 0 {
			first = took
		}
		if status != 200 {
			b.Fatalf("status %d", status)
		}
		if strings.Contains(sentBody(up), redactedDocument) {
			redacted++
		}
	}
	b.StopTimer()
	n := float64(b.N)
	extractN2, extractSum2 := histogramStats(metrics.PDFExtractSeconds)
	if int(extractN2-extractN) != b.N {
		b.Fatalf("%d extractions for %d requests", extractN2-extractN, b.N)
	}
	gotScored, gotDup, gotSkipped := windows("scored")-scored, windows("duplicate")-dup, windows("skipped")-skipped
	if gotSkipped != 0 {
		b.Errorf("%v windows skipped: not every window was scored", gotSkipped)
	}
	if got := (gotScored + gotDup) / n; got != float64(wantWindows) {
		b.Errorf("%v windows per request, the document has %d", got, wantWindows)
	}
	runtime.ReadMemStats(&ms)
	b.ReportMetric((extractSum2-extractSum)*1000/n, "extract_ms/op")
	b.ReportMetric(float64(scanned.Milliseconds())/n, "scan_ms/op")
	b.ReportMetric(float64(first.Milliseconds()), "first_ms")
	b.ReportMetric((gotScored+gotDup)/n, "windows/op")
	b.ReportMetric(gotSkipped/n, "skipped/op")
	b.ReportMetric(float64(tokens), "tokens")
	b.ReportMetric(float64(res.Pages), "pages")
	b.ReportMetric(float64(len(res.Text))/1024, "text_KiB")
	b.ReportMetric(float64(len(docs[0]))/1024, "body_KiB")
	b.ReportMetric(float64(redacted)/n, "redacted/op")
	b.ReportMetric(float64(maxRSS()-rssBefore)/(1<<20), "rss_peak_delta_MB")
	b.ReportMetric(float64(int64(ms.HeapSys)-int64(heapBefore))/(1<<20), "heap_sys_delta_MB")
}

// runPDFColdStart measures a fresh PDFium runtime per iteration: compiling
// the WebAssembly module, then the first document through it. The gateway
// pays this once per process, in the background at start-up (warm).
func runPDFColdStart(b *testing.B) {
	lim := pdfBenchLimits(b)
	doc := pdfBenchDocument(0)
	var compile, extract time.Duration
	rssBefore := maxRSS()
	b.ResetTimer()
	for range b.N {
		ex := pdftext.New(lim)
		start := time.Now()
		if err := ex.Warm(context.Background()); err != nil {
			b.Fatal(err)
		}
		compile += time.Since(start)
		start = time.Now()
		res, err := ex.Extract(context.Background(), doc, lim)
		if err != nil || res.Reason != pdftext.ReasonOK {
			b.Fatalf("extract: %v, reason %s", err, res.Reason)
		}
		extract += time.Since(start)
		if err := ex.Close(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	n := float64(b.N)
	b.ReportMetric(float64(compile.Milliseconds())/n, "compile_ms/op")
	b.ReportMetric(float64(extract.Milliseconds())/n, "first_extract_ms/op")
	b.ReportMetric(float64(maxRSS()-rssBefore)/(1<<20), "rss_peak_delta_MB")
}

// runPDFBenchAll runs cold_start and each API shape with the runner.
func runPDFBenchAll(b *testing.B, runner func(b *testing.B) *inference.Runner) {
	b.Run("cold_start", runPDFColdStart)
	for _, api := range pdfAPIs() {
		b.Run(api.name, func(b *testing.B) { runPDFBench(b, api, runner(b)) })
	}
}

// BenchmarkPDFDocument is the long-PDF benchmark with L1 only (no models):
// the extractor's cost and the gateway's overhead, without the classifier.
func BenchmarkPDFDocument(b *testing.B) {
	runPDFBenchAll(b, func(b *testing.B) *inference.Runner {
		runner, err := inference.NewRunner("")
		if err != nil {
			b.Fatal(err)
		}
		return runner
	})
}

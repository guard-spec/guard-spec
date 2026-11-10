// Package pdftext extracts the text a language model would see in a PDF.
//
// PDFium runs as a WebAssembly module inside wazero (github.com/klippa-app/
// go-pdfium in webassembly mode), so there is no cgo, no native library to
// ship and a malformed file cannot take the process down: every document is
// parsed in a fresh module instance with its own linear memory, capped by
// Limits.MemoryBytes, and interrupted when Limits.Timeout elapses.
//
// # What is extracted
//
// For every page, in page order:
//
//   - every text object, as PDFium's text page sees it. Colour, size, render
//     mode and position do not matter: white text, 1pt text, invisible text
//     (render mode 3) and text placed outside the media box are all included,
//     because a model that is handed the PDF sees them too;
//   - the /Contents of markup annotations (Text, FreeText, Highlight, ...);
//   - the value of form fields (the widget annotations of the AcroForm).
//
// Metadata (/Info, XMP), JavaScript, bookmarks, embedded files, link
// targets and Popup annotations (which only mirror their parent's contents)
// are skipped. Pages are separated by a form feed.
//
// # Outcomes
//
// Extract never panics and reports what happened in Result.Reason:
//
//   - ok: text was extracted;
//   - no_text: the file opened but has no text layer (scanned pages, images
//     only, empty pages);
//   - encrypted: the file needs a password (or an unsupported handler);
//   - damaged: PDFium could not parse the file, or a WebAssembly trap ended
//     the parse (this includes PDFium running out of its memory cap);
//   - timeout: Limits.Timeout elapsed; Text holds what was extracted so far;
//   - over_limit: the input is larger than MaxBytes, has more pages than
//     MaxPages, or the text exceeds MaxTextBytes. Text holds the partial
//     text; Truncated is set. Partial text must not be treated as a full
//     scan of the document;
//   - internal: the runtime could not be started or a Go panic was caught.
//     This is the only reason that comes with a non-nil error, apart from
//     the caller's own context ending (ctx.Err() is returned with reason
//     timeout).
//
// # Runtime
//
// The PDFium module is compiled on first use, which takes about 1.5 s on a
// laptop and a few hundred MB of memory that the Go runtime keeps; call Warm
// at start-up so no request pays for it. Each document runs in a fresh
// module instance (memory is returned when it is dropped) and at most
// Limits.MaxConcurrency instances run at once; further calls wait, and that
// wait counts against their Timeout. A timed-out call cancels the instance,
// which stops PDFium within microseconds (also under GC pressure); as a last
// resort the call gives up on the worker after a further 5 s.
package pdftext

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/klippa-app/go-pdfium"
	"github.com/klippa-app/go-pdfium/enums"
	pdfium_errors "github.com/klippa-app/go-pdfium/errors"
	"github.com/klippa-app/go-pdfium/references"
	"github.com/klippa-app/go-pdfium/requests"
	"github.com/klippa-app/go-pdfium/structs"
	"github.com/klippa-app/go-pdfium/webassembly"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/sys"
)

// Reasons reported in Result.Reason. See the package documentation.
const (
	ReasonOK        = "ok"
	ReasonNoText    = "no_text"
	ReasonEncrypted = "encrypted"
	ReasonDamaged   = "damaged"
	ReasonTimeout   = "timeout"
	ReasonOverLimit = "over_limit"
	ReasonInternal  = "internal"
)

// PageSeparator is written between the text of consecutive pages.
const PageSeparator = "\f"

const wasmPageSize = 64 * 1024

// Limits bounds one extraction. Zero fields take the defaults of
// DefaultLimits. MemoryBytes and MaxConcurrency size the shared runtime and
// are read when the runtime starts (first Extract or Warm); later calls
// with other values keep the running configuration.
type Limits struct {
	MaxBytes       int64         // Largest input accepted, in bytes.
	MaxPages       int64         // Pages scanned at most; more pages give over_limit.
	MaxTextBytes   int64         // Text returned at most, in bytes of UTF-8.
	Timeout        time.Duration // Wall clock budget for one document.
	MemoryBytes    uint64        // Linear memory cap of one PDFium instance.
	MaxConcurrency int           // Documents parsed in parallel; others wait.
}

// DefaultLimits returns the limits used for zero fields.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:       32 << 20,
		MaxPages:       600,
		MaxTextBytes:   4 << 20,
		Timeout:        10 * time.Second,
		MemoryBytes:    512 << 20,
		MaxConcurrency: max(1, runtime.GOMAXPROCS(0)/2),
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxPages <= 0 {
		l.MaxPages = d.MaxPages
	}
	if l.MaxTextBytes <= 0 {
		l.MaxTextBytes = d.MaxTextBytes
	}
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	if l.MemoryBytes == 0 {
		l.MemoryBytes = d.MemoryBytes
	}
	if l.MaxConcurrency <= 0 {
		l.MaxConcurrency = d.MaxConcurrency
	}
	return l
}

// Result is the outcome of one extraction.
type Result struct {
	Text      string // Extracted text, pages separated by PageSeparator.
	Pages     int    // Pages in the document (not the pages scanned).
	Truncated bool   // Text is incomplete (over_limit or timeout).
	Reason    string // One of the Reason constants.
}

// Extractor owns one PDFium runtime and its worker pool. The zero value is
// not usable; use New or the package-level functions.
type Extractor struct {
	mu     sync.Mutex
	limits Limits
	pool   pdfium.Pool
	closed bool
}

// New returns an extractor whose runtime is configured from lim
// (MemoryBytes and MaxConcurrency). The runtime starts lazily on the first
// Extract, or eagerly with Warm.
func New(lim Limits) *Extractor {
	return &Extractor{limits: lim.withDefaults()}
}

var (
	defaultMu sync.Mutex
	defaultEx *Extractor
)

func defaultExtractor(lim Limits) *Extractor {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultEx == nil {
		defaultEx = New(lim)
	}
	return defaultEx
}

// Extract runs the shared extractor. The runtime is started on first use
// with lim's MemoryBytes and MaxConcurrency.
func Extract(ctx context.Context, data []byte, lim Limits) (Result, error) {
	return defaultExtractor(lim).Extract(ctx, data, lim)
}

// Warm starts the shared extractor's runtime with DefaultLimits so that the
// first document does not pay for compiling the PDFium module.
func Warm(ctx context.Context) error {
	return defaultExtractor(DefaultLimits()).Warm(ctx)
}

// Warm compiles the PDFium module and checks that an instance can be
// created. It is safe to call concurrently and more than once.
func (e *Extractor) Warm(ctx context.Context) error {
	pool, err := e.init(ctx)
	if err != nil {
		return err
	}
	inst, err := pool.GetInstanceWithContext(ctx)
	if err != nil {
		return fmt.Errorf("pdftext: warm: %w", err)
	}
	return inst.Close()
}

// Close releases the runtime. Extract returns an internal error afterwards.
func (e *Extractor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.pool == nil {
		return nil
	}
	pool := e.pool
	e.pool = nil
	return pool.Close()
}

func (e *Extractor) init(ctx context.Context) (pdfium.Pool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, errors.New("pdftext: extractor is closed")
	}
	if e.pool != nil {
		return e.pool, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pages := e.limits.MemoryBytes / wasmPageSize
	if pages > 65536 {
		pages = 65536
	}
	if pages < 512 {
		pages = 512 // 32 MiB; the module itself declares 289 pages (18 MiB) as its minimum.
	}
	rc := wazero.NewRuntimeConfig().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling).
		WithMemoryLimitPages(uint32(pages)).
		WithCloseOnContextDone(true)
	pool, err := webassembly.Init(webassembly.Config{
		MaxTotal:      e.limits.MaxConcurrency,
		MaxIdle:       e.limits.MaxConcurrency,
		RuntimeConfig: rc,
		FSConfig:      wazero.NewFSConfig(), // no host directories are visible
		Stdout:        io.Discard,
		Stderr:        io.Discard,
	})
	if err != nil {
		return nil, fmt.Errorf("pdftext: start pdfium runtime: %w", err)
	}
	e.pool = pool
	return pool, nil
}

// Extract extracts the text of data within lim. The per-document fields of
// lim (MaxBytes, MaxPages, MaxTextBytes, Timeout) apply to this call.
func (e *Extractor) Extract(ctx context.Context, data []byte, lim Limits) (Result, error) {
	lim = lim.withDefaults()
	if int64(len(data)) > lim.MaxBytes {
		return Result{Reason: ReasonOverLimit, Truncated: true}, nil
	}
	if len(data) == 0 {
		return Result{Reason: ReasonDamaged}, nil
	}
	if err := ctx.Err(); err != nil {
		return Result{Reason: ReasonTimeout}, err
	}

	pool, err := e.init(ctx)
	if err != nil {
		return Result{Reason: ReasonInternal}, err
	}

	dctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	inst, err := pool.GetInstanceWithContext(dctx)
	if err != nil {
		if ctx.Err() != nil {
			return Result{Reason: ReasonTimeout}, ctx.Err()
		}
		if dctx.Err() != nil {
			return Result{Reason: ReasonTimeout}, nil
		}
		return Result{Reason: ReasonInternal}, fmt.Errorf("pdftext: get instance: %w", err)
	}

	c := &collector{max: lim.MaxTextBytes}
	done := make(chan outcome, 1)
	go func() {
		done <- runExtract(inst, data, lim, c)
	}()

	var out outcome
	killed := false
	select {
	case out = <-done:
	case <-dctx.Done():
		// Cancelling the worker context terminates the in-flight PDFium call
		// (WithCloseOnContextDone), so the goroutine returns promptly.
		killed = true
		_ = inst.Kill()
		select {
		case out = <-done:
		case <-time.After(5 * time.Second):
			out = outcome{reason: ReasonTimeout}
		}
	}
	if !killed {
		_ = inst.Close()
	}

	res := Result{Pages: out.pages, Text: c.text(), Truncated: c.truncated || out.truncated}
	switch {
	case out.err != nil && out.reason == ReasonInternal:
		res.Reason = ReasonInternal
		return res, out.err
	case ctx.Err() != nil:
		res.Reason = ReasonTimeout
		res.Truncated = true
		return res, ctx.Err()
	case dctx.Err() != nil || out.reason == ReasonTimeout:
		res.Reason = ReasonTimeout
		res.Truncated = true
		return res, nil
	}
	res.Reason = out.reason
	if res.Reason == ReasonOK {
		if c.truncated || out.truncated {
			res.Reason = ReasonOverLimit
		} else if strings.TrimSpace(res.Text) == "" {
			res.Reason = ReasonNoText
		}
	}
	return res, nil
}

type outcome struct {
	reason    string
	pages     int
	truncated bool
	err       error
}

// collector gathers text under a lock so that a timed-out extraction can
// still return what it had gathered.
type collector struct {
	mu        sync.Mutex
	sb        strings.Builder
	max       int64
	truncated bool
}

// add appends s and reports whether more text may follow.
func (c *collector) add(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return false
	}
	room := c.max - int64(c.sb.Len())
	if int64(len(s)) > room {
		c.sb.WriteString(cutUTF8(s, int(room)))
		c.truncated = true
		return false
	}
	c.sb.WriteString(s)
	return true
}

func (c *collector) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sb.String()
}

// cutUTF8 returns the longest prefix of s of at most n bytes that ends on a
// rune boundary.
func cutUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// runExtract does the PDFium calls. It runs in its own goroutine so that
// the caller can abandon it on timeout; it must not panic.
func runExtract(inst pdfium.Pdfium, data []byte, lim Limits, c *collector) (out outcome) {
	defer func() {
		if r := recover(); r != nil {
			out = outcome{reason: ReasonInternal, err: fmt.Errorf("pdftext: panic in extraction: %v", r)}
		}
	}()

	doc, err := inst.OpenDocument(&requests.OpenDocument{File: &data})
	if err != nil {
		return outcome{reason: classifyOpenError(err)}
	}
	defer inst.FPDF_CloseDocument(&requests.FPDF_CloseDocument{Document: doc.Document})

	pc, err := inst.FPDF_GetPageCount(&requests.FPDF_GetPageCount{Document: doc.Document})
	if err != nil {
		return outcome{reason: classifyCallError(err)}
	}
	out.pages = pc.PageCount
	if pc.PageCount <= 0 {
		return outcome{reason: ReasonOK, pages: pc.PageCount}
	}
	scan := pc.PageCount
	if int64(scan) > lim.MaxPages {
		scan = int(lim.MaxPages)
		out.truncated = true
	}

	// The form-fill environment resolves field values through inheritance
	// (a widget whose /V lives on its parent field). Without it we fall
	// back to the widget's own dictionary.
	var form *references.FPDF_FORMHANDLE
	if fh, err := inst.FPDFDOC_InitFormFillEnvironment(&requests.FPDFDOC_InitFormFillEnvironment{
		Document:     doc.Document,
		FormFillInfo: noopFormFillInfo(),
	}); err == nil {
		form = &fh.FormHandle
		defer inst.FPDFDOC_ExitFormFillEnvironment(&requests.FPDFDOC_ExitFormFillEnvironment{FormHandle: fh.FormHandle})
	}

	for i := 0; i < scan; i++ {
		if i > 0 && !c.add(PageSeparator) {
			break
		}
		more, err := extractPage(inst, doc.Document, i, form, c)
		if err != nil {
			out.reason = classifyCallError(err)
			return out
		}
		if !more {
			break
		}
	}
	out.reason = ReasonOK
	return out
}

func extractPage(inst pdfium.Pdfium, doc references.FPDF_DOCUMENT, index int, form *references.FPDF_FORMHANDLE, c *collector) (bool, error) {
	pg, err := inst.FPDF_LoadPage(&requests.FPDF_LoadPage{Document: doc, Index: index})
	if err != nil {
		// A page that does not load (bad object) is skipped, the rest of
		// the document is still useful.
		return true, nil
	}
	defer inst.FPDF_ClosePage(&requests.FPDF_ClosePage{Page: pg.Page})
	page := requests.Page{ByReference: &pg.Page}

	tp, err := inst.FPDFText_LoadPage(&requests.FPDFText_LoadPage{Page: page})
	if err != nil {
		return false, err
	}
	n, err := inst.FPDFText_CountChars(&requests.FPDFText_CountChars{TextPage: tp.TextPage})
	if err == nil && n.Count > 0 {
		txt, err := inst.FPDFText_GetText(&requests.FPDFText_GetText{TextPage: tp.TextPage, StartIndex: 0, Count: n.Count})
		if err != nil {
			_, _ = inst.FPDFText_ClosePage(&requests.FPDFText_ClosePage{TextPage: tp.TextPage})
			return false, err
		}
		if !c.add(normalizeNewlines(txt.Text)) {
			_, _ = inst.FPDFText_ClosePage(&requests.FPDFText_ClosePage{TextPage: tp.TextPage})
			return false, nil
		}
	}
	if _, err := inst.FPDFText_ClosePage(&requests.FPDFText_ClosePage{TextPage: tp.TextPage}); err != nil {
		return false, err
	}

	return extractAnnotations(inst, page, form, c)
}

func extractAnnotations(inst pdfium.Pdfium, page requests.Page, form *references.FPDF_FORMHANDLE, c *collector) (bool, error) {
	cnt, err := inst.FPDFPage_GetAnnotCount(&requests.FPDFPage_GetAnnotCount{Page: page})
	if err != nil {
		return false, err
	}
	for i := 0; i < cnt.Count; i++ {
		more, err := extractAnnotation(inst, page, i, form, c)
		if err != nil {
			return false, err
		}
		if !more {
			return false, nil
		}
	}
	return true, nil
}

func extractAnnotation(inst pdfium.Pdfium, page requests.Page, index int, form *references.FPDF_FORMHANDLE, c *collector) (bool, error) {
	an, err := inst.FPDFPage_GetAnnot(&requests.FPDFPage_GetAnnot{Page: page, Index: index})
	if err != nil {
		return true, nil // not an annotation dictionary; skip it
	}
	defer inst.FPDFPage_CloseAnnot(&requests.FPDFPage_CloseAnnot{Annotation: an.Annotation})

	st, err := inst.FPDFAnnot_GetSubtype(&requests.FPDFAnnot_GetSubtype{Annotation: an.Annotation})
	if err != nil {
		return false, err
	}
	var value string
	switch st.Subtype {
	case enums.FPDF_ANNOT_SUBTYPE_POPUP, enums.FPDF_ANNOT_SUBTYPE_LINK:
		return true, nil
	case enums.FPDF_ANNOT_SUBTYPE_WIDGET:
		if form != nil {
			v, err := inst.FPDFAnnot_GetFormFieldValue(&requests.FPDFAnnot_GetFormFieldValue{FormHandle: *form, Annotation: an.Annotation})
			if err == nil {
				value = v.FormFieldValue
			}
		}
		if value == "" {
			if v, err := inst.FPDFAnnot_GetStringValue(&requests.FPDFAnnot_GetStringValue{Annotation: an.Annotation, Key: "V"}); err == nil {
				value = v.Value
			}
		}
	default:
		if v, err := inst.FPDFAnnot_GetStringValue(&requests.FPDFAnnot_GetStringValue{Annotation: an.Annotation, Key: "Contents"}); err == nil {
			value = v.Value
		}
	}
	value = strings.TrimSpace(normalizeNewlines(value))
	if value == "" {
		return true, nil
	}
	return c.add("\n" + value + "\n"), nil
}

func normalizeNewlines(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// classifyOpenError maps the failure of OpenDocument to a reason.
func classifyOpenError(err error) string {
	switch {
	case errors.Is(err, pdfium_errors.ErrPassword), errors.Is(err, pdfium_errors.ErrSecurity):
		return ReasonEncrypted
	}
	return classifyCallError(err)
}

// classifyCallError maps the failure of any PDFium call to a reason. A
// module closed by the timeout surfaces as sys.ExitError, everything else
// (format errors, WebAssembly traps, out-of-memory aborts) is damaged.
func classifyCallError(err error) string {
	var exit *sys.ExitError
	if errors.As(err, &exit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	return ReasonDamaged
}

// noopFormFillInfo satisfies go-pdfium's required callbacks without doing
// anything: we only read field values and never render, focus or script.
func noopFormFillInfo() structs.FPDF_FORMFILLINFO {
	return structs.FPDF_FORMFILLINFO{
		FFI_Invalidate:         func(references.FPDF_PAGE, float64, float64, float64, float64) {},
		FFI_SetCursor:          func(enums.FXCT) {},
		FFI_SetTimer:           func(int, func(int)) int { return 0 },
		FFI_KillTimer:          func(int) {},
		FFI_GetLocalTime:       func() structs.FPDF_SYSTEMTIME { return structs.FPDF_SYSTEMTIME{} },
		FFI_GetPage:            func(references.FPDF_DOCUMENT, int) *references.FPDF_PAGE { return nil },
		FFI_GetRotation:        func(references.FPDF_PAGE) enums.FPDF_PAGE_ROTATION { return enums.FPDF_PAGE_ROTATION_NONE },
		FFI_ExecuteNamedAction: func(string) {},
	}
}

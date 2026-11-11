// Command benchlong measures the detector on long inputs: score
// distributions of benign text window by window, false positives as a text
// grows, thresholds that keep them in check, detection of payloads hidden in
// long text, and the CPU time and latency a long document costs.
//
//	make bench-long PROFILE=quick            # builds bench/long's corpus, then runs this
//	go run -tags onnx ./cmd/benchlong -corpus bench/.cache/long/quick
//	go run -tags onnx ./cmd/benchlong -docs ./my-texts -lang en   # your own .txt files
//
// It needs a binary built with -tags onnx (like cmd/onnxbench, it compiles
// without the tag and then stops with onnx.ErrUnavailable) and the models
// (MODEL_DIR, L2_MODEL_DIR, ... as for the gateway). The detector is built
// the way cmd/eval builds -detector fusion-ml (ml.ConfigFromEnv, ml.Build,
// inference.FusedBackend), so it runs the gateway's fused and calibrated code.
//
// These paths are measured, in process:
//
//   - "l2": the classifier alone on every 256-token window of the whole
//     text (onnx.Classifier.ScoreWindows, no window cap), Platt-calibrated as
//     in the fusion: what one window contributes;
//   - one per -layers entry ("l1", "l1,l2", ...): the fused detector on every
//     2048-byte chunk of the text, cut the way the gateway cuts untrusted
//     text (24 KiB segments, then chunks; see chunk.go) but with no 16-chunk
//     cap: the score the gateway compares with its 0.85 block threshold.
//     With -l2cap on (the default) each chunk gets the classifier's cap for
//     untrusted content (calibration.json l2_untrusted_max), as the gateway
//     applies it to documents and tool results.
//   - with -long on, "long": the gateway's long path (MAX_SCAN_TOKENS) as it
//     runs, ml.ScoreLong on 256-token windows with the document adjustment
//     and the calibration's long document rule (longpath.go); -dump writes
//     its window scores.
//
// Every text first goes through the gateway's sanitizer, as in cmd/eval.
// Output: bench/results/long-<host>.{json,md}. The JSON holds quantiles and
// rates, never raw scores or text.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guard-spec/guard-spec/internal/evalset"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// Doc is one line of the corpus (bench/long/build.py).
type Doc struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"` // benign, host, attack, control
	Lang      string   `json:"lang"`
	Genre     string   `json:"genre"`
	Text      string   `json:"text"`
	Source    string   `json:"source"`
	License   string   `json:"license"`
	Tokens    int      `json:"tokens"`
	Variant   string   `json:"variant,omitempty"`
	PayloadID string   `json:"payload_id,omitempty"`
	Category  string   `json:"category,omitempty"`
	Host      string   `json:"host,omitempty"`
	Spans     [][2]int `json:"spans,omitempty"`
	Split     string   `json:"split,omitempty"` // dev or holdout (bench/long/build.py split_of)
}

// Dev/holdout slices (eval/README.md): the last hex digit of a SHA-256 is
// 0-7 for dev and 8-f for holdout. The corpus carries the split in every
// document (build.py hashes the payload id of attack and control documents,
// the document id otherwise); documents without it (-docs .txt files) hash
// their id here.
const (
	splitDev     = "dev"
	splitHoldout = "holdout"
)

func splitOf(d Doc) string {
	if d.Split != "" {
		return d.Split
	}
	return splitOfKey(d.ID)
}

func splitOfKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	if sum[len(sum)-1]&0x0f < 8 {
		return splitDev
	}
	return splitHoldout
}

const (
	blockThreshold = evalset.InjectionBlockThreshold // 0.85, the gateway's block threshold
	anomalyBlock   = evalset.AnomalyBlockThreshold
	l2Layer        = "l2"
	gevBlock       = 16 // units per block maximum in the GEV fit
)

var nGrid = []int{1, 16, 64, 256, 1024, 2630}

func main() {
	var (
		corpus     = flag.String("corpus", "", "corpus directory with docs.jsonl (bench/long/build.py)")
		docsDir    = flag.String("docs", "", "directory of .txt files to measure instead of a corpus (benign text)")
		lang       = flag.String("lang", "unknown", "language label of -docs files")
		profile    = flag.String("profile", "", "profile label for the report (quick, full, ...)")
		layersFlag = flag.String("layers", "l1;l1,l2", "fused layer sets, separated by ';' (l3 optional: l1,l2,l3)")
		concFlag   = flag.String("conc", "1,2,4", "parallel chunks per document for the latency runs")
		intra      = flag.Int("intra", -1, "ONNX Runtime intra-op threads for the score pass (-1: $INFERENCE_INTRA_OP_THREADS or the gateway default; 0: ORT default)")
		intraList  = flag.String("latency-intra", "1,0", "intra-op threads for the latency runs (0: ORT default)")
		latMax     = flag.Int("latency-max-tokens", 50000, "largest document used in the latency runs")
		workers    = flag.Int("workers", 0, "documents scored in parallel in the score pass (0: the largest -conc)")
		seed       = flag.Uint64("seed", 20261109, "seed of the bootstrap draws")
		draws      = flag.Int("draws", 20000, "bootstrap draws per n")
		host       = flag.String("host", "", "host label for the output name (default: hostname)")
		out        = flag.String("out", "", "output JSON (default bench/results/long-<host>.json; the .md goes next to it)")
		skipLat    = flag.Bool("skip-latency", false, "skip the latency runs")
		l2cap      = flag.String("l2cap", "on", "apply the classifier's cap for untrusted content (calibration.json l2_untrusted_max) to the fused chunks, as the gateway does on documents: on or off")
		longFlag   = flag.String("long", "off", "also measure the gateway's long path (MAX_SCAN_TOKENS: 256-token windows fused l1,l2, the document adjustment) as layer \"long\": on or off")
		corrFlag   = flag.String("corroboration", "on", "code corroboration on the long path's windows, as the gateway's default for documents (TOOL_CODE_CORROBORATION): on or off")
		longDoc    = flag.String("longdoc", "on", "apply the classifier's long document rule (calibration.json long_doc) on the long path, as the gateway does: on or off")
		l2Pass     = flag.String("l2pass", "on", "score the classifier alone on every window (layer \"l2\"): on or off")
		dump       = flag.String("dump", "", "write the long path's window scores (no text) to <dump>-dev.jsonl.gz and <dump>-holdout.jsonl.gz")
	)
	flag.Parse()
	slog.SetLogLoggerLevel(slog.LevelWarn)
	if (*corpus == "") == (*docsDir == "") {
		fatal(errors.New("give exactly one of -corpus and -docs"))
	}
	concs, err := parseInts(*concFlag)
	if err != nil {
		fatal(fmt.Errorf("-conc: %w", err))
	}
	intras, err := parseInts(*intraList)
	if err != nil {
		fatal(fmt.Errorf("-latency-intra: %w", err))
	}
	var layerSets []string
	if *layersFlag != "none" {
		layerSets = strings.Split(*layersFlag, ";")
	}
	useCap, err := parseOnOff("-l2cap", *l2cap)
	if err != nil {
		fatal(err)
	}
	opts := engineOpts{useCap: useCap}
	for _, f := range []struct {
		name, v string
		dst     *bool
	}{{"-long", *longFlag, &opts.long}, {"-corroboration", *corrFlag, &opts.corroborate},
		{"-longdoc", *longDoc, &opts.longDoc}, {"-l2pass", *l2Pass, &opts.l2Pass}} {
		if *f.dst, err = parseOnOff(f.name, f.v); err != nil {
			fatal(err)
		}
	}
	if *dump != "" && !opts.long {
		fatal(errors.New("-dump needs -long on"))
	}
	if len(layerSets) == 0 && !opts.long {
		fatal(errors.New("-layers none needs -long on"))
	}

	var docs []Doc
	var corpusSHA string
	if *corpus != "" {
		docs, corpusSHA, err = loadCorpus(*corpus)
	} else {
		docs, err = loadTxt(*docsDir, *lang)
	}
	if err != nil {
		fatal(err)
	}
	ortVer, err := onnx.RuntimeVersion()
	if err != nil {
		fatal(err)
	}
	if *host == "" {
		h, _ := os.Hostname()
		*host = h
	}
	*host = sanitizeLabel(*host)
	if *out == "" {
		*out = filepath.Join("bench", "results", "long-"+*host+".json")
	}

	ctx := context.Background()
	if *intra >= 0 {
		_ = os.Setenv(onnx.EnvIntraOpThreads, strconv.Itoa(*intra))
	}
	e, err := newEngine(ctx, layerSets, opts)
	if err != nil {
		fatal(err)
	}
	if *dump != "" {
		e.dump = newDumper(*dump)
	}
	rep := Report{Header: header(e, ortVer, *profile, corpusSHA, *host, len(docs)), Notes: reportNotes}

	w := *workers
	if w <= 0 {
		w = slices0Max(concs)
	}
	logf("score pass: %d documents, %d workers, layers %v", len(docs), w, e.names())
	res, pass := e.scoreAll(ctx, docs, w)
	rep.ScorePass = pass
	if err := e.dump.close(); err != nil {
		fatal(err)
	}
	_ = e.close()

	if !*skipLat && len(layerSets) > 0 {
		rep.Latency = latencyRuns(ctx, layerSets, docs, concs, intras, *latMax, useCap)
	}

	analyse(&rep, docs, res, e.names(), *seed, *draws)
	if err := writeReport(&rep, *out); err != nil {
		fatal(err)
	}
	logf("wrote %s and %s", *out, strings.TrimSuffix(*out, ".json")+".md")
}

var reportNotes = []string{
	"Scores are calibrated probabilities: l2 is the classifier's Platt-calibrated risk per 256-token window (64-token overlap); the fused rows are the gateway's injection score per 2048-byte chunk (24 KiB segments, no 16-chunk cap).",
	"The block threshold is the gateway's 0.85. T(n) is the threshold that keeps a benign text of n units (windows or chunks) under 1% false positives: the larger of a block-bootstrap q99 of the maximum over n contiguous units and a GEV extrapolation fitted to 16-unit block maxima on the logit scale.",
	"Vietnamese thresholds are provisional: the Vietnamese benign corpus is smaller and less varied than the English one.",
	"Attack payloads are attack rows of the eval/ dev half (the eval/ holdout half is never used); TPR counts a document as detected when its maximum reaches the threshold. Hidden-character payloads are stripped by the sanitizer, which raises the anomaly score instead (the 'gateway' column also counts anomaly >= 0.6).",
	"split_far places the two halves of a payload about 1,500 tokens apart, so no window sees both: a known limitation of window scoring.",
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "benchlong:", err)
	os.Exit(1)
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

func parseInts(s string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad number %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// parseOnOff reads an on|off flag (on when empty), as cmd/eval does.
func parseOnOff(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%s must be on or off, not %q", name, v)
}

func slices0Max(x []int) int {
	m := 1
	for _, v := range x {
		m = max(m, v)
	}
	return m
}

var labelRe = regexp.MustCompile(`[^a-z0-9.-]+`)

func sanitizeLabel(s string) string {
	s = labelRe.ReplaceAllString(strings.ToLower(s), "-")
	return strings.Trim(s, "-.")
}

// ---------------------------------------------------------------------------
// Corpus

func loadCorpus(dir string) ([]Doc, string, error) {
	p := filepath.Join(dir, "docs.jsonl")
	f, err := os.Open(p)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var docs []Doc
	for sc.Scan() {
		var d Doc
		if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
			return nil, "", fmt.Errorf("%s:%d: %w", p, len(docs)+1, err)
		}
		docs = append(docs, d)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	return docs, hex.EncodeToString(h.Sum(nil)), nil
}

func loadTxt(dir, lang string) ([]Doc, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .txt files in %s", dir)
	}
	sort.Strings(paths)
	var docs []Doc
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		docs = append(docs, Doc{ID: filepath.Base(p), Kind: "benign", Lang: lang, Genre: "user", Text: string(b), Source: "user"})
	}
	return docs, nil
}

// ---------------------------------------------------------------------------
// Detector

type detector struct {
	name    string
	backend inference.FusedBackend
	adjust  inference.ChunkAdjust // the classifier's cap for untrusted content (nil: none)
	stack   *ml.Stack
}

type engine struct {
	l2     *onnx.Classifier
	cal    fusion.Calibration
	benign int
	l2Dir  string
	l2Name string
	capped bool // a detector applies the classifier's cap for untrusted content
	dets   []detector
	opts   engineOpts
	long   *longDet // the gateway's long path (-long on)
	dump   *dumper  // -dump
}

// engineOpts are the switches of the score pass.
type engineOpts struct {
	useCap      bool // the classifier's cap on the fused chunks and the long path
	long        bool // the long path as layer "long"
	corroborate bool // code corroboration on the long path
	longDoc     bool // the long document rule on the long path
	l2Pass      bool // layer "l2"
}

// newEngine builds the L2 window scorer and one fused detector per layer set,
// as cmd/eval newMLDetector does (ml.ConfigFromEnv, ml.Build). With useCap
// the fused chunks get the classifier's cap for untrusted content
// (ml.Stack.UntrustedAdjust), as the gateway applies it to documents and tool
// results; a calibration without a cap leaves the scores unchanged.
func newEngine(ctx context.Context, layerSets []string, opts engineOpts) (*engine, error) {
	useCap := opts.useCap
	cfg, err := ml.ConfigFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	dir, err := ml.ResolveL2Dir(cfg)
	if err != nil {
		return nil, err
	}
	c, err := onnx.NewClassifier(dir, onnx.Options{MaxChunks: -1})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	m, err := ml.NewL2Model(dir, c, c)
	if err != nil {
		return nil, err
	}
	e := &engine{l2: c, cal: m.Cal.Platt, benign: c.BenignIndex(), l2Dir: dir, l2Name: m.Name, opts: opts}
	if opts.long {
		if e.long, err = newLongDet(ctx, cfg, useCap, opts.corroborate, opts.longDoc); err != nil {
			return nil, err
		}
		if useCap && e.long.stack.UntrustedAdjust() != nil {
			e.capped = true
		}
	}
	for _, ls := range layerSets {
		lc := cfg
		if lc.Layers, err = ml.ParseLayers(ls); err != nil {
			return nil, err
		}
		stack, err := ml.Build(ctx, lc, nil)
		if err != nil {
			return nil, err
		}
		if stack.Degraded() {
			_ = stack.Close()
			return nil, errors.New("model layers unavailable:\n  " + strings.Join(stack.Problems, "\n  "))
		}
		name := ml.LayerKey(stack.Active) + "/" + stack.Fusion
		d := detector{name: name, backend: inference.FusedBackend{F: stack.Fuser}, stack: stack}
		if useCap {
			d.adjust = stack.UntrustedAdjust()
			if d.adjust != nil {
				e.capped = true
			}
		}
		e.dets = append(e.dets, d)
	}
	return e, nil
}

func (e *engine) close() error {
	errs := []error{e.l2.Close()}
	if e.long != nil {
		errs = append(errs, e.long.stack.Close())
	}
	for _, d := range e.dets {
		errs = append(errs, d.stack.Close())
	}
	return errors.Join(errs...)
}

// names are the layers in report order: l2, then the fused detectors, then
// the long path.
func (e *engine) names() []string {
	var out []string
	if e.opts.l2Pass {
		out = append(out, l2Layer)
	}
	for _, d := range e.dets {
		out = append(out, d.name)
	}
	if e.long != nil {
		out = append(out, longLayer)
	}
	return out
}

// docScore is one document's scores: per layer, one value per unit (window
// or chunk), in text order. Only the analysis reads it; nothing is written.
type docScore struct {
	anomaly  float64
	rejected bool
	tokens   int
	units    map[string][]float64
	// top is a layer's document score when it is not the largest unit (the
	// long path with a long document rule).
	top map[string]float64
	err error
}

// max is the document's score on layer: its largest unit, or the long
// path's document score.
func (r docScore) max(layer string) float64 {
	if v, ok := r.top[layer]; ok {
		return v
	}
	return maxOf(r.units[layer])
}

// scoreL2 scores every 256-token window of text with the classifier alone
// and returns the calibrated risks and the token count.
func (e *engine) scoreL2(ctx context.Context, text string) ([]float64, int, error) {
	ws, err := e.l2.ScoreWindows(ctx, text)
	if err != nil {
		return nil, 0, err
	}
	out := make([]float64, len(ws))
	for i, w := range ws {
		out[i] = e.cal.Apply(1 - float64(w.Probs[e.benign]))
	}
	return out, ws[len(ws)-1].End, nil
}

// scoreFused scores the gateway's chunks of text with d, k chunks at a time.
func scoreFused(ctx context.Context, d detector, text string, k int) ([]float64, error) {
	units := fusedUnits(text)
	out := make([]float64, len(units))
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
		next  = make(chan int)
	)
	for range max(1, k) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				chunk := text[units[i].start:units[i].end]
				s, err := d.backend.Run(ctx, chunk)
				if err != nil {
					mu.Lock()
					first = errors.Join(first, err)
					mu.Unlock()
					continue
				}
				out[i] = float64(d.adjust.Apply(chunk, s[0]).Confidence)
			}
		}()
	}
	for i := range units {
		next <- i
	}
	close(next)
	wg.Wait()
	return out, first
}

func (e *engine) scoreDoc(ctx context.Context, d Doc) docScore {
	r := docScore{units: map[string][]float64{}, top: map[string]float64{}}
	dd := DumpDoc{ID: d.ID, Kind: d.Kind, Lang: d.Lang, Genre: d.Genre, Split: splitOf(d), Tokens: d.Tokens,
		Variant: d.Variant, PayloadID: d.PayloadID, Host: d.Host, Spans: d.Spans}
	cleaned, rep, err := sanitizer.Sanitize(d.Text)
	if err != nil {
		// No score: the gateway rejects the text before any model sees it
		// (counted in the gateway column of the false-positive tables).
		logf("  %s: rejected by the sanitizer (%v)", d.ID, err)
		r.rejected = true
		dd.Rejected = true
		r.err = e.dump.write(dd)
		return r
	}
	r.anomaly = float64(rep.AnomalyScore)
	if e.opts.l2Pass {
		if r.units[l2Layer], r.tokens, r.err = e.scoreL2(ctx, cleaned); r.err != nil {
			return r
		}
	}
	for _, det := range e.dets {
		if r.units[det.name], r.err = scoreFused(ctx, det, cleaned, 1); r.err != nil {
			return r
		}
	}
	if e.long != nil {
		ws, top, err := e.long.score(ctx, cleaned)
		if err != nil {
			r.err = err
			return r
		}
		u := make([]float64, len(ws))
		for i, w := range ws {
			u[i] = float64(w.Score.Confidence)
		}
		r.units[longLayer], r.top[longLayer] = u, top
		if r.tokens == 0 {
			r.tokens, _ = e.l2.TokenCount(cleaned)
		}
		dd.Anomaly, dd.Scored, dd.Bytes, dd.DocScore, dd.Windows = r.anomaly, r.tokens, len(cleaned), top, dumpWindows(ws)
		if len(d.Spans) > 0 && d.Kind != "benign" {
			sp, ok := payloadSpans(d, cleaned)
			dd.PayloadSpans, dd.Intact = sp, &ok
		}
		r.err = e.dump.write(dd)
	}
	return r
}

// ScorePass is the throughput of the score pass: all documents, `workers`
// at a time.
type ScorePass struct {
	Docs     int     `json:"docs"`
	Tokens   int     `json:"tokens"`
	Workers  int     `json:"workers"`
	WallS    float64 `json:"wall_s"`
	CPUS     float64 `json:"cpu_s"`
	Windows  int     `json:"l2_windows"`
	Chunks   int     `json:"fused_chunks"`
	TokensPS float64 `json:"tokens_per_s"`
}

func (e *engine) scoreAll(ctx context.Context, docs []Doc, workers int) ([]docScore, ScorePass) {
	res := make([]docScore, len(docs))
	next := make(chan int)
	var wg sync.WaitGroup
	var done sync.WaitGroup
	start, cpu0 := time.Now(), cpuSeconds()
	progress := make(chan struct{}, len(docs))
	done.Add(1)
	go func() {
		defer done.Done()
		n := 0
		for range progress {
			n++
			if n%25 == 0 || n == len(docs) {
				logf("  %d/%d documents, %s", n, len(docs), time.Since(start).Round(time.Second))
			}
		}
	}()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				res[i] = e.scoreDoc(ctx, docs[i])
				if res[i].err != nil {
					fatal(fmt.Errorf("%s: %w", docs[i].ID, res[i].err))
				}
				progress <- struct{}{}
			}
		}()
	}
	// Longest first, so that the pass does not end on one big document.
	order := make([]int, len(docs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return len(docs[order[a]].Text) > len(docs[order[b]].Text) })
	for _, i := range order {
		next <- i
	}
	close(next)
	wg.Wait()
	close(progress)
	done.Wait()
	p := ScorePass{Docs: len(docs), Workers: workers, WallS: time.Since(start).Seconds(), CPUS: cpuSeconds() - cpu0}
	for _, r := range res {
		p.Tokens += r.tokens
		p.Windows += max(len(r.units[l2Layer]), len(r.units[longLayer]))
		if len(e.dets) > 0 {
			p.Chunks += len(r.units[e.dets[0].name])
		}
	}
	p.TokensPS = float64(p.Tokens) / p.WallS
	return res, p
}

// ---------------------------------------------------------------------------
// Latency

// Latency is one latency configuration over the latency documents, run one
// document at a time.
type Latency struct {
	Path  string   `json:"path"`  // "l2" (whole text, batched windows) or a fused detector (chunks)
	Intra int      `json:"intra"` // ONNX Runtime intra-op threads (0: ORT default)
	K     int      `json:"k"`     // chunks scored in parallel per document (fused paths)
	Docs  []LatDoc `json:"docs"`
	// Totals over Docs.
	MSPerWindow  float64 `json:"ms_per_window"`
	WindowsPerS  float64 `json:"windows_per_s"`
	TokensPerS   float64 `json:"tokens_per_s"`
	CPUSPer1kTok float64 `json:"cpu_s_per_1k_tokens"`
	Tokens10s    int     `json:"max_tokens_in_10s"`
}

// LatDoc is one document's wall time and CPU time in one configuration.
type LatDoc struct {
	ID      string  `json:"id"`
	Tokens  int     `json:"tokens"`
	Units   int     `json:"units"`
	Windows int     `json:"l2_windows"`
	WallMS  float64 `json:"wall_ms"`
	CPUS    float64 `json:"cpu_s"`
}

func latencyDocs(docs []Doc, maxTokens int) []Doc {
	var out []Doc
	for _, d := range docs {
		if d.Kind == "benign" && (d.Genre == "wiki" || d.Genre == "user") && d.Tokens <= maxTokens {
			out = append(out, d)
		}
	}
	return out
}

func latencyRuns(ctx context.Context, layerSets []string, docs []Doc, concs, intras []int, maxTokens int, useCap bool) []Latency {
	sel := latencyDocs(docs, maxTokens)
	if len(sel) == 0 {
		logf("latency: no document of at most %d tokens; skipped", maxTokens)
		return nil
	}
	// The most complete layer set is the one the gateway runs with models.
	last := layerSets[len(layerSets)-1]
	var out []Latency
	for _, intra := range intras {
		_ = os.Setenv(onnx.EnvIntraOpThreads, strconv.Itoa(intra))
		e, err := newEngine(ctx, []string{last}, engineOpts{useCap: useCap, l2Pass: true})
		if err != nil {
			fatal(err)
		}
		det := e.dets[0]
		// Warm-up: first runs allocate.
		if _, _, err := e.scoreL2(ctx, sel[0].Text[:min(len(sel[0].Text), 8000)]); err != nil {
			fatal(err)
		}
		if _, err := scoreFused(ctx, det, sel[0].Text[:min(len(sel[0].Text), 8000)], 1); err != nil {
			fatal(err)
		}
		l := Latency{Path: l2Layer, Intra: intra, K: 1}
		for _, d := range sel {
			cleaned, _, err := sanitizer.Sanitize(d.Text)
			if err != nil {
				continue
			}
			t0, c0 := time.Now(), cpuSeconds()
			s, toks, err := e.scoreL2(ctx, cleaned)
			if err != nil {
				fatal(err)
			}
			l.Docs = append(l.Docs, LatDoc{ID: d.ID, Tokens: toks, Units: len(s), Windows: len(s),
				WallMS: ms(time.Since(t0)), CPUS: cpuSeconds() - c0})
		}
		out = append(out, finishLatency(l))
		logf("latency: %s intra=%d done", l2Layer, intra)
		for _, k := range concs {
			if k < 1 {
				continue
			}
			l := Latency{Path: det.name, Intra: intra, K: k}
			for _, d := range sel {
				cleaned, _, err := sanitizer.Sanitize(d.Text)
				if err != nil {
					continue
				}
				windows := 0
				for _, u := range fusedUnits(cleaned) {
					n, _ := e.l2.TokenCount(cleaned[u.start:u.end])
					windows += windowsFor(n)
				}
				toks, _ := e.l2.TokenCount(cleaned)
				t0, c0 := time.Now(), cpuSeconds()
				s, err := scoreFused(ctx, det, cleaned, k)
				if err != nil {
					fatal(err)
				}
				l.Docs = append(l.Docs, LatDoc{ID: d.ID, Tokens: toks, Units: len(s), Windows: windows,
					WallMS: ms(time.Since(t0)), CPUS: cpuSeconds() - c0})
			}
			out = append(out, finishLatency(l))
			logf("latency: %s intra=%d k=%d done", det.name, intra, k)
		}
		_ = e.close()
	}
	return out
}

// windowsFor is the number of 256-token windows (254 content tokens, a new
// one every 190) that L2 runs for a chunk of n content tokens.
func windowsFor(n int) int {
	if n <= 254 {
		return 1
	}
	return 1 + (n-254+189)/190
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func finishLatency(l Latency) Latency {
	var wall, cpu float64
	var toks, wins int
	for _, d := range l.Docs {
		wall += d.WallMS
		cpu += d.CPUS
		toks += d.Tokens
		wins += d.Windows
	}
	if wall > 0 && wins > 0 && toks > 0 {
		l.MSPerWindow = wall / float64(wins)
		l.WindowsPerS = float64(wins) / (wall / 1000)
		l.TokensPerS = float64(toks) / (wall / 1000)
		l.CPUSPer1kTok = cpu / float64(toks) * 1000
		l.Tokens10s = int(l.TokensPerS * 10)
	}
	return l
}

// ---------------------------------------------------------------------------
// Header

// Header describes the run: model, runtime, machine, commit.
type Header struct {
	Date           string   `json:"date"`
	Host           string   `json:"host"`
	Profile        string   `json:"profile,omitempty"`
	CorpusSHA256   string   `json:"corpus_sha256,omitempty"`
	Docs           int      `json:"docs"`
	Model          string   `json:"model"`
	ModelSHA256    string   `json:"model_sha256"`
	ORT            string   `json:"onnxruntime"`
	CPU            string   `json:"cpu"`
	VCPU           int      `json:"vcpu"`
	GOOS           string   `json:"goos"`
	GOARCH         string   `json:"goarch"`
	Commit         string   `json:"commit"`
	MaxConcurrency int      `json:"inference_max_concurrency"`
	IntraOp        string   `json:"inference_intra_op_threads"`
	Layers         []string `json:"layers"`
	Block          float64  `json:"block_threshold"`
	L2Cap          bool     `json:"l2_cap"` // the classifier's cap for untrusted content applied to the fused chunks
}

func header(e *engine, ort, profile, corpusSHA, host string, docs int) Header {
	return Header{
		Date: time.Now().UTC().Format(time.RFC3339), Host: host, Profile: profile, CorpusSHA256: corpusSHA,
		Docs: docs, Model: e.l2Name, ModelSHA256: fileSHA(onnx.ResolveModelFile(e.l2Dir, onnx.Options{})), ORT: ort,
		CPU: cpuModel(), VCPU: runtime.NumCPU(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Commit: commit(),
		MaxConcurrency: onnx.MaxConcurrencyFromEnv(), IntraOp: os.Getenv(onnx.EnvIntraOpThreads),
		Layers: e.names(), Block: blockThreshold, L2Cap: e.capped,
	}
}

func fileSHA(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cpuModel() string {
	if runtime.GOOS == "darwin" {
		if b, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(ln, ":"); ok && strings.TrimSpace(k) == "model name" {
				return strings.TrimSpace(v)
			}
		}
	}
	return runtime.GOARCH
}

func commit() string {
	if s := os.Getenv("GITHUB_SHA"); s != "" {
		return s[:min(12, len(s))]
	}
	if b, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output(); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Analysis

// Report is the JSON output.
type Report struct {
	Header     Header    `json:"header"`
	ScorePass  ScorePass `json:"score_pass"`
	Latency    []Latency `json:"latency,omitempty"`
	Quantiles  []QRow    `json:"window_quantiles"`
	DocFPR     []FPRRow  `json:"doc_fpr"`
	Thresholds []TRow    `json:"thresholds"`
	TPR        []TPRRow  `json:"tpr,omitempty"`
	// The same tables on the dev and holdout slices (Split set on every
	// row); the totals above are unchanged by the slicing.
	DocFPRSplit []FPRRow `json:"doc_fpr_by_split,omitempty"`
	TPRSplit    []TPRRow `json:"tpr_by_split,omitempty"`
	Notes       []string `json:"notes"`
}

// QRow is the distribution of per-unit scores of benign documents.
type QRow struct {
	Layer string `json:"layer"`
	Genre string `json:"genre"`
	Lang  string `json:"lang"`
	Quantiles
}

// FPRRow is the share of benign documents of one size whose maximum reaches
// the block threshold.
type FPRRow struct {
	Layer   string  `json:"layer"`
	Split   string  `json:"split,omitempty"` // dev or holdout in DocFPRSplit; empty in DocFPR (all documents)
	Lang    string  `json:"lang"`
	Size    string  `json:"size"`
	Docs    int     `json:"docs"`
	Units   float64 `json:"mean_units"`
	FPR     float64 `json:"fpr"`
	Gateway float64 `json:"gateway_fpr"` // also counting sanitizer anomaly / rejection
	// Rejected is the number of Docs the sanitizer rejected before scoring (no
	// units, no score; counted in Gateway, never in FPR).
	Rejected int `json:"rejected,omitempty"`
}

// TRow holds the thresholds T(n) for one layer and language.
type TRow struct {
	Layer       string   `json:"layer"`
	Lang        string   `json:"lang"`
	StreamUnits int      `json:"stream_units"`
	GEV         *GEV     `json:"gev,omitempty"`
	Points      []TPoint `json:"points"`
	Provisional bool     `json:"provisional,omitempty"`
}

// TPoint is T(n) and its two estimates.
type TPoint struct {
	N        int      `json:"n"`
	Boot     float64  `json:"bootstrap_q99"`
	GEV      *float64 `json:"gev_q99,omitempty"` // nil: too few block maxima to fit
	Gumbel   *float64 `json:"gumbel_q99,omitempty"`
	T        float64  `json:"t"`
	FPRBlock float64  `json:"fpr_at_block"`
	Short    bool     `json:"short_stream,omitempty"`
}

// TPRRow is detection of one attack variant.
type TPRRow struct {
	Layer     string  `json:"layer"`
	Split     string  `json:"split,omitempty"` // dev or holdout in TPRSplit; empty in TPR (all documents)
	Lang      string  `json:"lang"`
	Variant   string  `json:"variant"`
	Docs      int     `json:"docs"`
	Units     float64 `json:"mean_units"`
	AtBlock   float64 `json:"tpr_at_block"`
	AtTn      float64 `json:"tpr_at_tn"`
	Gateway   float64 `json:"gateway_tpr"`
	HostFlags int     `json:"host_flagged,omitempty"` // hosts whose own maximum reaches the block threshold
}

func maxOf(x []float64) float64 {
	m := math.Inf(-1)
	for _, v := range x {
		m = max(m, v)
	}
	return m
}

// nominalTokens is the size a document is labelled with: the corpus's own
// count (build.py, the text as built) when it has one, else the tokens the
// classifier saw. The sanitizer can shorten a document a lot before scoring
// (its HTML stripping on code, documentation or RFC text; see docs/benchmark.md
// "Long documents"), and a 200k document that reached the model as 140k
// tokens still belongs in the 200k cell.
func nominalTokens(d Doc, r docScore) int {
	if d.Tokens > 0 {
		return d.Tokens
	}
	return r.tokens
}

func sizeLabel(tokens int) string {
	for _, g := range []int{20000, 50000, 100000, 200000, 500000} {
		if tokens >= g*9/10 && tokens <= g*11/10 {
			return fmt.Sprintf("%dk", g/1000)
		}
	}
	switch {
	case tokens < 20000:
		return "<20k"
	case tokens < 100000:
		return "20k-100k"
	default:
		return ">100k"
	}
}

func analyse(rep *Report, docs []Doc, res []docScore, layers []string, seed uint64, draws int) {
	langs := []string{}
	seenLang := map[string]bool{}
	for _, d := range docs {
		if !seenLang[d.Lang] {
			seenLang[d.Lang] = true
			langs = append(langs, d.Lang)
		}
	}
	sort.Strings(langs)

	// Window quantiles by genre x lang x layer (benign documents).
	type gl struct{ g, l string }
	for _, layer := range layers {
		groups := map[gl][]float64{}
		var keys []gl
		for i, d := range docs {
			if d.Kind != "benign" {
				continue
			}
			k := gl{d.Genre, d.Lang}
			if _, ok := groups[k]; !ok {
				keys = append(keys, k)
			}
			groups[k] = append(groups[k], res[i].units[layer]...)
		}
		sort.Slice(keys, func(a, b int) bool {
			if keys[a].l != keys[b].l {
				return keys[a].l < keys[b].l
			}
			return keys[a].g < keys[b].g
		})
		for _, k := range keys {
			if len(groups[k]) == 0 {
				continue // every document of the group was rejected by the sanitizer: no scores
			}
			rep.Quantiles = append(rep.Quantiles, QRow{Layer: layer, Genre: k.g, Lang: k.l, Quantiles: summarize(groups[k], blockThreshold)})
		}
	}

	// Document-level FPR by size: all benign documents, then the dev and
	// holdout slices (the totals do not depend on the slicing).
	all := func(Doc) bool { return true }
	inSplit := func(s string) func(Doc) bool { return func(d Doc) bool { return splitOf(d) == s } }
	rep.DocFPR = docFPR(docs, res, layers, "", all)
	for _, s := range []string{splitDev, splitHoldout} {
		rep.DocFPRSplit = append(rep.DocFPRSplit, docFPR(docs, res, layers, s, inSplit(s))...)
	}

	// T(n) per layer and language, from the benign stream in document order.
	type tkey struct{ layer, lang string }
	streams := map[tkey][]float64{}
	for i, d := range docs {
		if d.Kind != "benign" {
			continue
		}
		for _, layer := range layers {
			streams[tkey{layer, d.Lang}] = append(streams[tkey{layer, d.Lang}], res[i].units[layer]...)
		}
	}
	tn := map[tkey]func(n int) float64{}
	for _, layer := range layers {
		for _, lang := range langs {
			k := tkey{layer, lang}
			st := streams[k]
			if len(st) == 0 {
				continue
			}
			row := TRow{Layer: layer, Lang: lang, StreamUnits: len(st), Provisional: lang == "vi"}
			g, ok := fitGEV(st, gevBlock)
			if ok {
				row.GEV = &g
			}
			cache := map[int]BlockMax{}
			boot := func(n int) BlockMax {
				if b, ok := cache[n]; ok {
					return b
				}
				rng := rand.New(rand.NewPCG(seed, uint64(n)))
				b := blockMax(st, n, draws, blockThreshold, rng)
				cache[n] = b
				return b
			}
			t := func(n int) float64 {
				v := boot(n).Q99
				if ok {
					v = max(v, g.Quantile99(n, false))
				}
				return v
			}
			tn[k] = t
			for _, n := range nGrid {
				b := boot(n)
				p := TPoint{N: n, Boot: b.Q99, T: t(n), FPRBlock: b.FPRBlock, Short: b.Short}
				if ok {
					p.GEV, p.Gumbel = ptr(g.Quantile99(n, false)), ptr(g.Quantile99(n, true))
				}
				row.Points = append(row.Points, p)
			}
			rep.Thresholds = append(rep.Thresholds, row)
		}
	}

	// TPR per attack variant (and the payload-alone control): all attack
	// documents, then the dev and holdout slices. T(n) comes from the whole
	// benign stream in every case.
	hostMax := map[string]map[string]float64{} // host id -> layer -> max
	for i, d := range docs {
		if d.Kind == "host" {
			hostMax[d.ID] = map[string]float64{}
			for _, layer := range layers {
				hostMax[d.ID][layer] = res[i].max(layer)
			}
		}
	}
	tnOf := func(layer, lang string, units int) (float64, bool) {
		f := tn[tkey{layer, lang}]
		if f == nil {
			return 0, false
		}
		return f(max(1, units)), true
	}
	rep.TPR = attackTPR(docs, res, layers, hostMax, tnOf, "", all)
	for _, s := range []string{splitDev, splitHoldout} {
		rep.TPRSplit = append(rep.TPRSplit, attackTPR(docs, res, layers, hostMax, tnOf, s, inSplit(s))...)
	}
}

// docFPR is the share of benign documents (those that `keep` accepts) of
// each language and size whose maximum reaches the block threshold, per
// layer. split labels the rows (empty for all documents).
func docFPR(docs []Doc, res []docScore, layers []string, split string, keep func(Doc) bool) []FPRRow {
	var out []FPRRow
	for _, layer := range layers {
		type key struct{ lang, size string }
		type acc struct {
			n, hit, gw, rej int
			units           int
		}
		m := map[key]*acc{}
		var keys []key
		for i, d := range docs {
			if d.Kind != "benign" || !keep(d) {
				continue
			}
			k := key{d.Lang, sizeLabel(nominalTokens(d, res[i]))}
			a := m[k]
			if a == nil {
				a = &acc{}
				m[k] = a
				keys = append(keys, k)
			}
			mx := res[i].max(layer)
			a.n++
			a.units += len(res[i].units[layer])
			if mx >= blockThreshold {
				a.hit++
			}
			if mx >= blockThreshold || res[i].rejected || res[i].anomaly >= anomalyBlock {
				a.gw++
			}
			if res[i].rejected {
				a.rej++
			}
		}
		sort.Slice(keys, func(a, b int) bool {
			if keys[a].lang != keys[b].lang {
				return keys[a].lang < keys[b].lang
			}
			return sizeOrder(keys[a].size) < sizeOrder(keys[b].size)
		})
		for _, k := range keys {
			a := m[k]
			out = append(out, FPRRow{Layer: layer, Split: split, Lang: k.lang, Size: k.size, Docs: a.n,
				Units: float64(a.units) / float64(a.n), FPR: float64(a.hit) / float64(a.n), Gateway: float64(a.gw) / float64(a.n), Rejected: a.rej})
		}
	}
	return out
}

// attackTPR is the detection rate of the attack and control documents that
// `keep` accepts, per layer, language and variant. tnOf gives T(n) of a
// layer and language for n units (ok false when no benign stream exists).
func attackTPR(docs []Doc, res []docScore, layers []string, hostMax map[string]map[string]float64,
	tnOf func(layer, lang string, units int) (float64, bool), split string, keep func(Doc) bool) []TPRRow {
	var out []TPRRow
	for _, layer := range layers {
		type key struct{ lang, variant string }
		type acc struct{ n, units, b, t, gw, hf int }
		m := map[key]*acc{}
		var keys []key
		for i, d := range docs {
			if (d.Kind != "attack" && d.Kind != "control") || !keep(d) {
				continue
			}
			k := key{d.Lang, d.Variant}
			a := m[k]
			if a == nil {
				a = &acc{}
				m[k] = a
				keys = append(keys, k)
			}
			u := res[i].units[layer]
			mx := res[i].max(layer)
			a.n++
			a.units += len(u)
			if mx >= blockThreshold {
				a.b++
			}
			if t, ok := tnOf(layer, d.Lang, len(u)); ok && mx >= t {
				a.t++
			}
			if mx >= blockThreshold || res[i].rejected || res[i].anomaly >= anomalyBlock {
				a.gw++
			}
			if hm, ok := hostMax[d.Host]; ok && hm[layer] >= blockThreshold {
				a.hf++
			}
		}
		sort.Slice(keys, func(a, b int) bool {
			if keys[a].lang != keys[b].lang {
				return keys[a].lang < keys[b].lang
			}
			return variantOrder(keys[a].variant) < variantOrder(keys[b].variant)
		})
		for _, k := range keys {
			a := m[k]
			n := float64(a.n)
			out = append(out, TPRRow{Layer: layer, Split: split, Lang: k.lang, Variant: k.variant, Docs: a.n,
				Units: float64(a.units) / n, AtBlock: float64(a.b) / n, AtTn: float64(a.t) / n, Gateway: float64(a.gw) / n, HostFlags: a.hf})
		}
	}
	return out
}

func sizeOrder(s string) int {
	for i, v := range []string{"<20k", "20k", "50k", "20k-100k", "100k", ">100k", "200k", "500k"} {
		if s == v {
			return i
		}
	}
	return 99
}

var variants = []string{"control", "pos_start", "pos_end", "pos_random", "straddle_window", "straddle_chunk",
	"straddle_segment", "split_adjacent", "split_far", "hidden_zero_width", "hidden_tags",
	"genre_code_comment", "genre_json_field"}

func variantOrder(v string) int {
	for i, x := range variants {
		if x == v {
			return i
		}
	}
	return len(variants)
}

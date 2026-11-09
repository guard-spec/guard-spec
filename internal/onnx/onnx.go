// Package onnx runs transformer classifiers and embedding models in-process
// through ONNX Runtime (github.com/yalue/onnxruntime_go) with the Hugging Face
// Rust tokenizer (github.com/daulet/tokenizers). See docs/adr/0001-onnx-runtime.md.
//
// A model directory holds model.onnx, tokenizer.json and config.json, as laid
// out by `go run ./cmd/models pull` (models/cache/<name>/).
//
// The real backend needs cgo and the build tag `onnx`:
//
//	CGO_ENABLED=1 CGO_LDFLAGS=-L$PWD/.onnx/lib go build -tags onnx ./...
//
// and, at run time, the ONNX Runtime shared library (ONNXRUNTIME_LIB). Without
// the tag the package still compiles: NewClassifier and NewEmbedder return
// ErrUnavailable, so the default `go build`/`go test` work with CGO_ENABLED=0.
//
// Long inputs are never truncated. They are tokenized once, split into windows
// of MaxLength tokens (special tokens included) that overlap by Stride tokens,
// and every window is scored. A classifier reports the per-label maximum over a
// text's windows, so a payload hidden after benign padding is still seen.
package onnx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// File names inside a model directory.
const (
	ModelFile      = "model.onnx"
	ModelInt8File  = "model_int8.onnx"
	ThresholdsFile = "thresholds.json"
	TokenizerFile  = "tokenizer.json"
	ConfigFile     = "config.json"
)

// Environment variables read by this package.
const (
	// EnvMaxConcurrency bounds concurrent model runs process-wide (default: NumCPU).
	EnvMaxConcurrency = "INFERENCE_MAX_CONCURRENCY"
	// EnvIntraOpThreads sets ONNX Runtime intra-op threads per session (default: min(4, NumCPU) on Linux, ORT's choice elsewhere; 0 = ORT's choice).
	EnvIntraOpThreads = "INFERENCE_INTRA_OP_THREADS"
	// EnvLibraryPath is the path of libonnxruntime.{so,dylib}.
	EnvLibraryPath = "ONNXRUNTIME_LIB"
)

var (
	// ErrUnavailable means the binary was built without the `onnx` tag or cgo.
	ErrUnavailable = errors.New("onnx: runtime not compiled in (build with CGO_ENABLED=1 -tags onnx)")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("onnx: model closed")
	// ErrInputTooLong means a text needs more than MaxChunks windows. Callers
	// must reject the input: scoring only a prefix would let padding hide a payload.
	ErrInputTooLong = errors.New("onnx: input too long to scan")
)

// Options tune a model. Zero values pick the defaults.
type Options struct {
	// MaxLength is the window size in tokens, special tokens included.
	// Default for a classifier: max_len from thresholds.json if present;
	// otherwise config.json max_position_embeddings, capped at 512.
	MaxLength int
	// Stride is the overlap between consecutive windows in tokens (default 64).
	Stride int
	// BatchSize is the number of windows per ONNX run (default 8).
	BatchSize int
	// MaxChunks caps the windows per text (default 64; negative: no cap).
	MaxChunks int
	// Limiter bounds concurrent runs. Default: DefaultLimiter(), shared by all models.
	Limiter *Limiter
	// Head for classifiers. Default HeadAuto (config.json problem_type).
	Head Head
	// ModelFile is the model file name inside the directory. Default: the
	// first of model.onnx and model_int8.onnx that exists.
	ModelFile string
	// IntraOpThreads for ONNX Runtime. Default: $INFERENCE_INTRA_OP_THREADS, else see EnvIntraOpThreads.
	IntraOpThreads int
	// Prefix is text put at the start of every window, after the special
	// tokens, such as "query:" for e5 models. Repeating it per window keeps
	// every window of a long text in the form the model was trained on.
	Prefix string
}

const (
	defaultMaxLength = 512
	defaultStride    = 64
	defaultBatchSize = 8
	defaultMaxChunks = 64
)

// ---------------------------------------------------------------------------
// Concurrency limiter

// Limiter is a counting semaphore that bounds concurrent model runs.
type Limiter struct{ sem chan struct{} }

// NewLimiter returns a limiter admitting n concurrent runs (n < 1 means 1).
func NewLimiter(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{sem: make(chan struct{}, n)}
}

// Acquire blocks until a slot is free or ctx is done.
func (l *Limiter) Acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot taken by Acquire.
func (l *Limiter) Release() { <-l.sem }

// Cap is the number of concurrent runs allowed.
func (l *Limiter) Cap() int { return cap(l.sem) }

// MaxConcurrencyFromEnv returns $INFERENCE_MAX_CONCURRENCY, or runtime.NumCPU()
// when unset or invalid.
func MaxConcurrencyFromEnv() int {
	if n, err := strconv.Atoi(os.Getenv(EnvMaxConcurrency)); err == nil && n > 0 {
		return n
	}
	return runtime.NumCPU()
}

var (
	defaultLimiterOnce sync.Once
	defaultLimiter     *Limiter
)

// DefaultLimiter is the process-wide limiter sized by MaxConcurrencyFromEnv.
func DefaultLimiter() *Limiter {
	defaultLimiterOnce.Do(func() { defaultLimiter = NewLimiter(MaxConcurrencyFromEnv()) })
	return defaultLimiter
}

// ---------------------------------------------------------------------------
// Backend seams (real implementation in backend_ort.go, stub otherwise)

type modelKind int

const (
	kindClassifier modelKind = iota // output: logits [batch, labels]
	kindEmbedder                    // output: last_hidden_state [batch, seq, hidden]
)

// tokenizer turns text into content token ids: no special tokens, no
// truncation, no padding. Implementations must be safe for concurrent use.
type tokenizer interface {
	Encode(text string) ([]int64, error)
	// Specials returns the ids the post-processor puts before and after a
	// single sequence ([CLS] … [SEP], <s> … </s>).
	Specials() (prefix, suffix []int64)
	Close() error
}

// session runs one batch. ids, mask and typeIDs are [batch*seq] row-major.
// It returns the selected output flattened, with its shape. Implementations
// must be safe for concurrent use and should stop early when ctx is done.
type session interface {
	Run(ctx context.Context, ids, mask, typeIDs []int64, batch, seq int) ([]float32, []int64, error)
	Close() error
}

// ResolveModelFile returns the model path inside dir: Options.ModelFile if set,
// else the first of model.onnx and model_int8.onnx that exists.
func ResolveModelFile(dir string, o Options) string {
	if o.ModelFile != "" {
		return filepath.Join(dir, o.ModelFile)
	}
	for _, name := range []string{ModelFile, ModelInt8File} {
		if p := filepath.Join(dir, name); fileExists(p) {
			return p
		}
	}
	return filepath.Join(dir, ModelFile)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------------------------------------------------------------------------
// Model core shared by Classifier and Embedder

type modelConfig struct {
	ID2Label              map[string]string `json:"id2label"`
	ProblemType           string            `json:"problem_type"`
	MaxPositionEmbeddings int               `json:"max_position_embeddings"`
	PadTokenID            *int64            `json:"pad_token_id"`
}

func readConfig(dir string) (modelConfig, error) {
	var c modelConfig
	data, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", ConfigFile, err)
	}
	return c, nil
}

// labelsFromID2Label orders id2label by numeric id; ids must be 0..n-1.
func labelsFromID2Label(m map[string]string) ([]string, error) {
	if len(m) == 0 {
		return nil, errors.New("config.json has no id2label")
	}
	labels := make([]string, len(m))
	for k, v := range m {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= len(m) || labels[i] != "" {
			return nil, fmt.Errorf("config.json id2label: bad id %q", k)
		}
		labels[i] = v
	}
	return labels, nil
}

type model struct {
	tok    tokenizer
	sess   session
	prefix []int64
	suffix []int64
	pad    int64

	maxLen, stride, batchSize, maxChunks int
	lim                                  *Limiter

	mu     sync.RWMutex // held for reading by running calls, for writing by Close
	closed bool
}

func newModel(tok tokenizer, sess session, cfg modelConfig, o Options) (*model, error) {
	m := &model{tok: tok, sess: sess, lim: o.Limiter}
	m.prefix, m.suffix = tok.Specials()
	if o.Prefix != "" {
		ids, err := tok.Encode(o.Prefix)
		if err != nil {
			return nil, fmt.Errorf("onnx: tokenize prefix: %w", err)
		}
		m.prefix = append(append([]int64(nil), m.prefix...), ids...)
	}
	if cfg.PadTokenID != nil {
		m.pad = *cfg.PadTokenID
	}
	m.maxLen = o.MaxLength
	if m.maxLen <= 0 {
		m.maxLen = defaultMaxLength
		if p := cfg.MaxPositionEmbeddings; p > 0 && p < m.maxLen {
			m.maxLen = p
		}
	}
	m.stride = o.Stride
	if m.stride <= 0 {
		m.stride = defaultStride
	}
	m.batchSize = o.BatchSize
	if m.batchSize <= 0 {
		m.batchSize = defaultBatchSize
	}
	m.maxChunks = o.MaxChunks
	if m.maxChunks == 0 {
		m.maxChunks = defaultMaxChunks
	}
	if m.lim == nil {
		m.lim = DefaultLimiter()
	}
	window := m.maxLen - len(m.prefix) - len(m.suffix)
	if window < 1 {
		return nil, fmt.Errorf("onnx: MaxLength %d leaves no room for content", m.maxLen)
	}
	if m.stride >= window {
		return nil, fmt.Errorf("onnx: Stride %d must be smaller than the content window %d", m.stride, window)
	}
	return m, nil
}

func (m *model) close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return errors.Join(m.sess.Close(), m.tok.Close())
}

func (m *model) tokenCount(text string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, ErrClosed
	}
	ids, err := m.tok.Encode(text)
	return len(ids), err
}

// chunk splits content ids into windows of at most maxLen tokens (special
// tokens added) overlapping by stride. An empty text gives one window.
func (m *model) chunk(ids []int64) ([][]int64, error) {
	window := m.maxLen - len(m.prefix) - len(m.suffix)
	step := window - m.stride
	var out [][]int64
	for start := 0; ; start += step {
		end := start + window
		if end > len(ids) {
			end = len(ids)
		}
		seq := make([]int64, 0, len(m.prefix)+end-start+len(m.suffix))
		seq = append(seq, m.prefix...)
		seq = append(seq, ids[start:end]...)
		seq = append(seq, m.suffix...)
		out = append(out, seq)
		if m.maxChunks > 0 && len(out) > m.maxChunks {
			return nil, fmt.Errorf("%w: %d tokens, more than %d windows", ErrInputTooLong, len(ids), m.maxChunks)
		}
		if end == len(ids) {
			return out, nil
		}
	}
}

// window is one chunk of one input text.
type window struct {
	text int
	pos  int // index of the window within its text
	ids  []int64
}

func (m *model) windows(texts []string) ([]window, error) {
	var ws []window
	for i, t := range texts {
		ids, err := m.tok.Encode(t)
		if err != nil {
			return nil, fmt.Errorf("tokenize text %d: %w", i, err)
		}
		chunks, err := m.chunk(ids)
		if err != nil {
			return nil, fmt.Errorf("text %d: %w", i, err)
		}
		for j, c := range chunks {
			ws = append(ws, window{text: i, pos: j, ids: c})
		}
	}
	return ws, nil
}

// batchOut is the model output for one batch.
type batchOut struct {
	wins  []window  // windows in this batch, in row order
	seq   int       // padded sequence length
	mask  []int64   // [batch*seq]
	data  []float32 // selected output, flattened
	shape []int64
}

// run tokenizes, chunks and batches texts and calls fn once per batch, in order
// of increasing window length (less padding). fn is not called concurrently.
func (m *model) run(ctx context.Context, texts []string, fn func(b batchOut) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ErrClosed
	}
	ws, err := m.windows(texts)
	if err != nil {
		return err
	}
	sort.SliceStable(ws, func(a, b int) bool { return len(ws[a].ids) < len(ws[b].ids) })

	for start := 0; start < len(ws); start += m.batchSize {
		end := min(start+m.batchSize, len(ws))
		b := batchOut{wins: ws[start:end]}
		for _, w := range b.wins {
			b.seq = max(b.seq, len(w.ids))
		}
		n := len(b.wins)
		ids := make([]int64, n*b.seq)
		b.mask = make([]int64, n*b.seq)
		typeIDs := make([]int64, n*b.seq)
		for r, w := range b.wins {
			row := ids[r*b.seq : (r+1)*b.seq]
			copy(row, w.ids)
			for j := len(w.ids); j < b.seq; j++ {
				row[j] = m.pad
			}
			for j := range w.ids {
				b.mask[r*b.seq+j] = 1
			}
		}
		lim := m.limiterFor(ctx)
		if err := lim.Acquire(ctx); err != nil {
			return err
		}
		b.data, b.shape, err = m.sess.Run(ctx, ids, b.mask, typeIDs, n, b.seq)
		lim.Release()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := fn(b); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Classifier

// Head is how a classifier turns logits into probabilities.
type Head int

const (
	// HeadAuto reads config.json problem_type: "multi_label_classification"
	// means HeadSigmoid, anything else HeadSoftmax.
	HeadAuto Head = iota
	// HeadSoftmax: single-label, probabilities sum to 1 (ProtectAI).
	HeadSoftmax
	// HeadSigmoid: multi-label, one independent probability per label
	// (guardspec-classifier).
	HeadSigmoid
)

func (h Head) String() string {
	switch h {
	case HeadSoftmax:
		return "softmax"
	case HeadSigmoid:
		return "sigmoid"
	}
	return "auto"
}

// Classifier is a sequence-classification model. Safe for concurrent use.
type Classifier struct {
	m      *model
	labels []string
	head   Head
	benign int // index of the benign/safe label, or -1
}

// NewClassifier loads the model file (see Options.ModelFile), dir/tokenizer.json
// and the label names from dir/config.json id2label. The head (softmax or
// sigmoid) comes from Options.Head or config.json problem_type.
func NewClassifier(dir string, o Options) (*Classifier, error) {
	cfg, err := readConfig(dir)
	if err != nil {
		return nil, err
	}
	labels, err := labelsFromID2Label(cfg.ID2Label)
	if err != nil {
		return nil, err
	}
	head := o.Head
	if head == HeadAuto {
		head = HeadSoftmax
		if cfg.ProblemType == "multi_label_classification" {
			head = HeadSigmoid
		}
	}
	if o.MaxLength <= 0 {
		o.MaxLength = trainedMaxLen(dir)
	}
	tok, sess, err := newBackend(dir, kindClassifier, o)
	if err != nil {
		return nil, err
	}
	m, err := newModel(tok, sess, cfg, o)
	if err != nil {
		_ = sess.Close()
		_ = tok.Close()
		return nil, err
	}
	return newClassifier(m, labels, head), nil
}

// trainedMaxLen reads max_len from dir/thresholds.json (written by the
// guardspec-classifier training), or returns 0.
func trainedMaxLen(dir string) int {
	data, err := os.ReadFile(filepath.Join(dir, ThresholdsFile))
	if err != nil {
		return 0
	}
	var t struct {
		MaxLen int `json:"max_len"`
	}
	if json.Unmarshal(data, &t) != nil {
		return 0
	}
	return t.MaxLen
}

func newClassifier(m *model, labels []string, head Head) *Classifier {
	c := &Classifier{m: m, labels: labels, head: head, benign: -1}
	for i, l := range labels {
		if isBenignLabel(l) {
			c.benign = i
			break
		}
	}
	return c
}

// isBenignLabel matches the "no attack" label of the supported models.
func isBenignLabel(l string) bool {
	switch strings.ToLower(l) {
	case "benign", "safe":
		return true
	}
	return false
}

// Labels are the label names, in the order of Score's probabilities.
func (c *Classifier) Labels() []string { return append([]string(nil), c.labels...) }

// Head is the activation in use (HeadSoftmax or HeadSigmoid).
func (c *Classifier) Head() Head { return c.head }

// LabelIndex returns the position of a label in Labels, or -1.
func (c *Classifier) LabelIndex(name string) int {
	for i, l := range c.labels {
		if l == name {
			return i
		}
	}
	return -1
}

// BenignIndex is the position of the benign/safe label ("benign", "SAFE"), or -1.
func (c *Classifier) BenignIndex() int { return c.benign }

// Score returns per-label probabilities for each text: softmax of the logits
// for a single-label head, an independent sigmoid per label for a multi-label
// head. A text longer than one window is scored window by window and every
// label takes its worst case over the windows: the minimum for the benign/safe
// label, the maximum for every other label. The values of a chunked text need
// not sum to 1.
func (c *Classifier) Score(ctx context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	activate := softmax
	if c.head == HeadSigmoid {
		activate = sigmoid
	}
	err := c.m.run(ctx, texts, func(b batchOut) error {
		if len(b.shape) != 2 || int(b.shape[0]) != len(b.wins) || int(b.shape[1]) != len(c.labels) {
			return fmt.Errorf("onnx: classifier output shape %v, want [%d %d]", b.shape, len(b.wins), len(c.labels))
		}
		nl := len(c.labels)
		for r, w := range b.wins {
			p := activate(b.data[r*nl : (r+1)*nl])
			if out[w.text] == nil {
				out[w.text] = p
				continue
			}
			for k := range p {
				if k == c.benign {
					out[w.text][k] = min(out[w.text][k], p[k])
				} else {
					out[w.text][k] = max(out[w.text][k], p[k])
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrNoBenignLabel means Risk was called on a model without a benign/safe label.
var ErrNoBenignLabel = errors.New("onnx: model has no benign/safe label")

// Risk returns 1 - p(benign) per text (for ProtectAI, 1 - p(SAFE) = p(INJECTION)).
// For a chunked text it uses the lowest p(benign) of any window.
func (c *Classifier) Risk(ctx context.Context, texts []string) ([]float32, error) {
	if c.benign < 0 {
		return nil, ErrNoBenignLabel
	}
	probs, err := c.Score(ctx, texts)
	if err != nil {
		return nil, err
	}
	out := make([]float32, len(probs))
	for i, p := range probs {
		out[i] = 1 - p[c.benign]
	}
	return out, nil
}

// TokenCount is the number of content tokens (no special tokens) in text.
func (c *Classifier) TokenCount(text string) (int, error) { return c.m.tokenCount(text) }

// Close frees the session and tokenizer after in-flight calls finish.
func (c *Classifier) Close() error { return c.m.close() }

// ---------------------------------------------------------------------------
// Embedder

// Embedder is a sentence-embedding model (mean pooling, L2 normalised).
// Safe for concurrent use.
type Embedder struct{ m *model }

// NewEmbedder loads dir/model.onnx and dir/tokenizer.json.
func NewEmbedder(dir string, o Options) (*Embedder, error) {
	cfg, err := readConfig(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tok, sess, err := newBackend(dir, kindEmbedder, o)
	if err != nil {
		return nil, err
	}
	m, err := newModel(tok, sess, cfg, o)
	if err != nil {
		_ = sess.Close()
		_ = tok.Close()
		return nil, err
	}
	return &Embedder{m: m}, nil
}

// Embed returns one unit-length vector per text: the mean of the last hidden
// state over real (unmasked) tokens. A text longer than one window gets the
// token-weighted mean over its windows, then L2 normalisation.
func (e *Embedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	sums := make([][]float64, len(texts))
	counts := make([]float64, len(texts))
	err := e.m.run(ctx, texts, func(b batchOut) error {
		if len(b.shape) != 3 || int(b.shape[0]) != len(b.wins) || int(b.shape[1]) != b.seq {
			return fmt.Errorf("onnx: embedder output shape %v, want [%d %d hidden]", b.shape, len(b.wins), b.seq)
		}
		hidden := int(b.shape[2])
		for r, w := range b.wins {
			if sums[w.text] == nil {
				sums[w.text] = make([]float64, hidden)
			}
			accumulateMasked(sums[w.text], b.data[r*b.seq*hidden:(r+1)*b.seq*hidden], b.mask[r*b.seq:(r+1)*b.seq], hidden)
			counts[w.text] += float64(len(w.ids))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([][]float32, len(texts))
	for i := range texts {
		out[i] = l2normalize(sums[i], counts[i])
	}
	return out, nil
}

// EmbedWindows returns, per text, one unit-length vector per window (see the
// package comment on chunking), in window order. Unlike Embed it does not
// average the windows, so a short passage inside a long text keeps its own
// vector.
func (e *Embedder) EmbedWindows(ctx context.Context, texts []string) ([][][]float32, error) {
	out := make([][][]float32, len(texts))
	err := e.m.run(ctx, texts, func(b batchOut) error {
		if len(b.shape) != 3 || int(b.shape[0]) != len(b.wins) || int(b.shape[1]) != b.seq {
			return fmt.Errorf("onnx: embedder output shape %v, want [%d %d hidden]", b.shape, len(b.wins), b.seq)
		}
		hidden := int(b.shape[2])
		for r, w := range b.wins {
			sum := make([]float64, hidden)
			accumulateMasked(sum, b.data[r*b.seq*hidden:(r+1)*b.seq*hidden], b.mask[r*b.seq:(r+1)*b.seq], hidden)
			for len(out[w.text]) <= w.pos {
				out[w.text] = append(out[w.text], nil)
			}
			out[w.text][w.pos] = l2normalize(sum, float64(len(w.ids)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TokenCount is the number of content tokens (no special tokens) in text.
func (e *Embedder) TokenCount(text string) (int, error) { return e.m.tokenCount(text) }

// Close frees the session and tokenizer after in-flight calls finish.
func (e *Embedder) Close() error { return e.m.close() }

// ---------------------------------------------------------------------------
// Math helpers

func sigmoid(logits []float32) []float32 {
	out := make([]float32, len(logits))
	for i, v := range logits {
		out[i] = float32(1 / (1 + math.Exp(-float64(v))))
	}
	return out
}

func softmax(logits []float32) []float32 {
	out := make([]float32, len(logits))
	if len(logits) == 0 {
		return out
	}
	mx := logits[0]
	for _, v := range logits[1:] {
		mx = max(mx, v)
	}
	var sum float64
	for i, v := range logits {
		e := math.Exp(float64(v - mx))
		out[i] = float32(e)
		sum += e
	}
	for i := range out {
		out[i] = float32(float64(out[i]) / sum)
	}
	return out
}

// accumulateMasked adds the rows of states ([seq*hidden]) whose mask is 1 into sum.
func accumulateMasked(sum []float64, states []float32, mask []int64, hidden int) {
	for t, on := range mask {
		if on == 0 {
			continue
		}
		row := states[t*hidden : (t+1)*hidden]
		for k, v := range row {
			sum[k] += float64(v)
		}
	}
}

// l2normalize turns a sum over n tokens into a unit vector (the mean has the
// same direction, so dividing by n is only for numerical range).
func l2normalize(sum []float64, n float64) []float32 {
	out := make([]float32, len(sum))
	if n == 0 {
		return out
	}
	var norm float64
	for _, v := range sum {
		norm += (v / n) * (v / n)
	}
	norm = math.Sqrt(norm)
	if norm == 0 {
		return out
	}
	for i, v := range sum {
		out[i] = float32(v / n / norm)
	}
	return out
}

//go:build onnx && cgo

package onnx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"

	"github.com/daulet/tokenizers"
	ort "github.com/yalue/onnxruntime_go"
)

// Available reports whether the ONNX Runtime backend is compiled in.
func Available() bool { return true }

var (
	envOnce sync.Once
	envErr  error
)

// libraryCandidates are tried in order when ONNXRUNTIME_LIB is unset.
func libraryCandidates() []string {
	name := "libonnxruntime.so"
	dirs := []string{"/usr/local/lib", "/usr/lib"}
	if runtime.GOOS == "darwin" {
		name = "libonnxruntime.dylib"
		dirs = []string{"/opt/homebrew/lib", "/usr/local/lib"}
	}
	var out []string
	for _, d := range append([]string{".onnx/lib"}, dirs...) {
		out = append(out, filepath.Join(d, name))
	}
	return out
}

// LibraryPath is the ONNX Runtime shared library that will be (or was) loaded.
func LibraryPath() string {
	if p := os.Getenv(EnvLibraryPath); p != "" {
		return p
	}
	for _, p := range libraryCandidates() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// initEnvironment loads the shared library once per process. The environment
// stays alive for the life of the process; sessions are freed by Close.
func initEnvironment() error {
	envOnce.Do(func() {
		lib := LibraryPath()
		if lib == "" {
			envErr = fmt.Errorf("onnx: libonnxruntime not found; set %s (tried %v)", EnvLibraryPath, libraryCandidates())
			return
		}
		ort.SetSharedLibraryPath(lib)
		if err := ort.InitializeEnvironment(); err != nil {
			envErr = fmt.Errorf("onnx: load %s: %w", lib, err)
		}
	})
	return envErr
}

// RuntimeVersion is the loaded ONNX Runtime version.
func RuntimeVersion() (string, error) {
	if err := initEnvironment(); err != nil {
		return "", err
	}
	return ort.GetVersion(), nil
}

func newBackend(dir string, kind modelKind, o Options) (tokenizer, session, error) {
	if err := initEnvironment(); err != nil {
		return nil, nil, err
	}
	tok, err := newHFTokenizer(filepath.Join(dir, TokenizerFile))
	if err != nil {
		return nil, nil, err
	}
	sess, err := newORTSession(ResolveModelFile(dir, o), kind, o)
	if err != nil {
		_ = tok.Close()
		return nil, nil, err
	}
	return tok, sess, nil
}

func intraOpThreads(o Options) int {
	if o.IntraOpThreads > 0 {
		return o.IntraOpThreads
	}
	if n, err := strconv.Atoi(os.Getenv(EnvIntraOpThreads)); err == nil && n >= 0 {
		return n // 0: let ORT decide
	}
	if runtime.GOOS == "linux" {
		// Measured in a linux/arm64 container on a 14-CPU host: ORT's default
		// (one spinning thread per core) was 3-7x slower than 4 threads, both
		// alone and with 4 concurrent calls. On macOS the ORT default was best.
		return min(defaultLinuxIntraOpThreads, runtime.NumCPU())
	}
	return 0
}

const defaultLinuxIntraOpThreads = 4

// ---------------------------------------------------------------------------
// Tokenizer

type hfTokenizer struct {
	tk             *tokenizers.Tokenizer
	prefix, suffix []int64
}

// newHFTokenizer loads tokenizer.json with its truncation and padding settings
// removed: chunking is done on the full token sequence by this package.
func newHFTokenizer(path string) (*hfTokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	doc["truncation"] = json.RawMessage("null")
	doc["padding"] = json.RawMessage("null")
	if data, err = json.Marshal(doc); err != nil {
		return nil, err
	}
	tk, err := tokenizers.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	t := &hfTokenizer{tk: tk}
	if err := t.findSpecials(); err != nil {
		_ = tk.Close()
		return nil, err
	}
	return t, nil
}

// findSpecials learns the post-processor's prefix and suffix by encoding a
// probe with and without special tokens.
func (t *hfTokenizer) findSpecials() error {
	const probe = "hello world"
	with, err := t.encode(probe, true)
	if err != nil {
		return err
	}
	without, err := t.encode(probe, false)
	if err != nil {
		return err
	}
	for i := 0; i+len(without) <= len(with); i++ {
		if slices.Equal(with[i:i+len(without)], without) {
			t.prefix = with[:i]
			t.suffix = with[i+len(without):]
			return nil
		}
	}
	return errors.New("onnx: cannot locate special tokens in the tokenizer's post-processor output")
}

func (t *hfTokenizer) encode(text string, special bool) ([]int64, error) {
	enc, err := t.tk.EncodeWithOptionsErr(text, special)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(enc.IDs))
	for i, v := range enc.IDs {
		ids[i] = int64(v)
	}
	return ids, nil
}

// EncodeOffsets is Encode with the byte span of each token in text (the
// Rust tokenizer reports byte offsets), for the long path (long.go).
func (t *hfTokenizer) EncodeOffsets(text string) ([]int64, [][2]int, error) {
	enc, err := t.tk.EncodeWithOptionsErr(text, false, tokenizers.WithReturnOffsets())
	if err != nil {
		return nil, nil, err
	}
	ids := make([]int64, len(enc.IDs))
	offs := make([][2]int, len(enc.IDs))
	for i, v := range enc.IDs {
		ids[i] = int64(v)
		if i < len(enc.Offsets) {
			offs[i] = [2]int{int(enc.Offsets[i][0]), int(enc.Offsets[i][1])}
		}
	}
	return ids, offs, nil
}

func (t *hfTokenizer) Encode(text string) ([]int64, error) { return t.encode(text, false) }
func (t *hfTokenizer) Specials() ([]int64, []int64)        { return t.prefix, t.suffix }
func (t *hfTokenizer) Close() error                        { return t.tk.Close() }

// ---------------------------------------------------------------------------
// Session

type ortSession struct {
	s          *ort.DynamicAdvancedSession
	inputs     []string // subset of input_ids, attention_mask, token_type_ids
	outputRank int
}

func newORTSession(path string, kind modelKind, o Options) (*ortSession, error) {
	ins, outs, err := ort.GetInputOutputInfo(path)
	if err != nil {
		return nil, fmt.Errorf("onnx: inspect %s: %w", path, err)
	}
	s := &ortSession{}
	for _, in := range ins {
		switch in.Name {
		case "input_ids", "attention_mask", "token_type_ids":
			s.inputs = append(s.inputs, in.Name)
		default:
			return nil, fmt.Errorf("onnx: %s has unsupported input %q", path, in.Name)
		}
	}
	if !slices.Contains(s.inputs, "input_ids") {
		return nil, fmt.Errorf("onnx: %s has no input_ids input", path)
	}
	output := ""
	want := map[modelKind][]string{
		kindClassifier: {"logits"},
		kindEmbedder:   {"last_hidden_state", "token_embeddings"},
	}[kind]
	s.outputRank = map[modelKind]int{kindClassifier: 2, kindEmbedder: 3}[kind]
	for _, name := range want {
		for _, out := range outs {
			if out.Name == name {
				output = name
			}
		}
		if output != "" {
			break
		}
	}
	if output == "" {
		for _, out := range outs { // fall back to the first output of the right rank
			if len(out.Dimensions) == s.outputRank {
				output = out.Name
				break
			}
		}
	}
	if output == "" {
		return nil, fmt.Errorf("onnx: %s has no rank-%d output", path, s.outputRank)
	}

	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, err
	}
	defer func() { _ = opts.Destroy() }()
	if n := intraOpThreads(o); n > 0 {
		if err := opts.SetIntraOpNumThreads(n); err != nil {
			return nil, err
		}
	}
	if err := opts.SetInterOpNumThreads(1); err != nil {
		return nil, err
	}
	if err := opts.SetGraphOptimizationLevel(ort.GraphOptimizationLevelEnableAll); err != nil {
		return nil, err
	}
	s.s, err = ort.NewDynamicAdvancedSession(path, s.inputs, []string{output}, opts)
	if err != nil {
		return nil, fmt.Errorf("onnx: load %s: %w", path, err)
	}
	return s, nil
}

func (s *ortSession) Run(ctx context.Context, ids, mask, typeIDs []int64, batch, seq int) ([]float32, []int64, error) {
	shape := ort.NewShape(int64(batch), int64(seq))
	values := make([]ort.Value, 0, len(s.inputs))
	defer func() {
		for _, v := range values {
			_ = v.Destroy()
		}
	}()
	for _, name := range s.inputs {
		data := map[string][]int64{"input_ids": ids, "attention_mask": mask, "token_type_ids": typeIDs}[name]
		t, err := ort.NewTensor(shape, data)
		if err != nil {
			return nil, nil, err
		}
		values = append(values, t)
	}

	ro, err := ort.NewRunOptions()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = ro.Destroy() }()
	stop := context.AfterFunc(ctx, func() { _ = ro.Terminate() })
	defer stop()

	outputs := []ort.Value{nil}
	if err := s.s.RunWithOptions(values, outputs, ro); err != nil {
		return nil, nil, err
	}
	defer func() { _ = outputs[0].Destroy() }()
	t, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, nil, fmt.Errorf("onnx: output is %T, want float32 tensor", outputs[0])
	}
	dims := t.GetShape()
	if len(dims) != s.outputRank {
		return nil, nil, fmt.Errorf("onnx: output shape %v, want rank %d", dims, s.outputRank)
	}
	return slices.Clone(t.GetData()), []int64(slices.Clone(dims)), nil
}

func (s *ortSession) Close() error { return s.s.Destroy() }

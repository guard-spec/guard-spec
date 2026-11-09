//go:build onnx && cgo

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// TestCodeLogChunks scores every chunk of each CODELOG_CORPUS row as the
// runner cuts it (2048-byte windows, 1792-byte stride) with the fuser and
// writes each chunk's calibrated layer scores and rules to CODELOG_OUT: the
// attribution side of the RF-476b4d30 measurement.
func TestCodeLogChunks(t *testing.T) {
	corpus := os.Getenv("CODELOG_CORPUS")
	if corpus == "" {
		t.Skip("CODELOG_CORPUS not set")
	}
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	if onnx.LibraryPath() == "" {
		t.Setenv(onnx.EnvLibraryPath, filepath.Join(root, ".onnx", "lib", "libonnxruntime.dylib"))
	}
	s, err := ml.Build(context.Background(), ml.Config{ModelDir: filepath.Join(root, "models"),
		Layers: [3]bool{true, true, true}, Fusion: "logreg", L1Floor: ml.DefaultL1Floor}, nil)
	if err != nil || s.Degraded() {
		t.Fatalf("%v %v", err, s.Problems)
	}
	defer s.Close()
	rows := readCodeLogCorpus(t, corpus)
	out, err := os.Create(os.Getenv("CODELOG_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	type chunkOut struct {
		ID       string             `json:"id"`
		Chunk    int                `json:"chunk"`
		Rejected bool               `json:"rejected,omitempty"`
		Anomaly  float32            `json:"anomaly"`
		Score    float64            `json:"score"`
		L1       float64            `json:"l1"`
		L2       float64            `json:"l2"`
		L3       float64            `json:"l3"`
		Floored  bool               `json:"floored"`
		Category string             `json:"category"`
		Rules    []string           `json:"rules"`
		Cats     map[string]float64 `json:"cats"`
		Text     string             `json:"text,omitempty"`
	}
	var mu sync.Mutex
	jobs := make(chan codeLogRow)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				cleaned, rep, err := sanitizer.Sanitize(r.Text)
				var res []chunkOut
				if err != nil {
					res = append(res, chunkOut{ID: r.ID, Rejected: true})
				}
				for i, c := range splitLikeRunner(cleaned) {
					f := s.Fuser.Score(context.Background(), c)
					o := chunkOut{ID: r.ID, Chunk: i, Anomaly: rep.AnomalyScore, Score: f.Score,
						L1: f.Layers[0], L2: f.Layers[1], L3: f.Layers[2], Floored: f.L1Floored,
						Category: f.Category, Rules: f.Rules, Cats: f.Categories}
					if f.Score >= 0.5 && os.Getenv("CODELOG_TEXT") != "" {
						o.Text = c
					}
					res = append(res, o)
				}
				mu.Lock()
				for _, o := range res {
					b, _ := json.Marshal(o)
					_, _ = out.Write(append(b, '\n'))
				}
				mu.Unlock()
			}
		}()
	}
	for _, r := range rows {
		jobs <- r
	}
	close(jobs)
	wg.Wait()
}

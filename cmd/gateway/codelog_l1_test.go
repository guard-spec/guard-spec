package main

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"unicode/utf8"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/rules"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// TestCodeLogL1 writes the calibrated L1 score of every chunk of each
// CODELOG_CORPUS row to CODELOG_OUT (RF-476b4d30 measurement; skipped
// without CODELOG_CORPUS).
func TestCodeLogL1(t *testing.T) {
	corpus := os.Getenv("CODELOG_CORPUS")
	if corpus == "" {
		t.Skip("CODELOG_CORPUS not set")
	}
	out, err := os.Create(os.Getenv("CODELOG_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	e := rules.New()
	enc := json.NewEncoder(out)
	for _, r := range readCodeLogCorpus(t, corpus) {
		cleaned, _, err := sanitizer.Sanitize(r.Text)
		if err != nil {
			continue
		}
		for i, c := range splitLikeRunner(cleaned) {
			res := e.Score(c)
			o := map[string]any{"id": r.ID, "chunk": i, "raw": res.Score,
				"l1": fusion.DefaultL1Calibration.Apply(res.Score), "decisive": res.Decisive, "rules": res.Rules}
			if len(res.Rules) > 0 && os.Getenv("CODELOG_TEXT") != "" {
				o["text"] = c
			}
			_ = enc.Encode(o)
		}
	}
}

type codeLogRow struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func readCodeLogCorpus(t *testing.T, path string) []codeLogRow {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var rows []codeLogRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r codeLogRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

// splitLikeRunner is inference.chunkText without the window cap.
func splitLikeRunner(text string) []string {
	const win, stride = 512 * 4, 448 * 4
	if len(text) <= win {
		return []string{text}
	}
	at := func(i int) int {
		for i > 0 && i < len(text) && !utf8.RuneStart(text[i]) {
			i--
		}
		return i
	}
	var out []string
	for start := 0; ; start = at(start + stride) {
		end := at(min(start+win, len(text)))
		out = append(out, text[start:end])
		if end == len(text) {
			return out
		}
	}
}

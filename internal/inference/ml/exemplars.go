package ml

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
)

// defaultExemplars is the L3 reference set: attacks of every category and
// benign prompts, EN and VI, picked deterministically from the training split
// (train/data/train.jsonl, never eval/ or the validation split) by
// `go run ./cmd/calibrate exemplars`. Every row keeps its source and license
// (all permit redistribution, see train/DATA_LICENSES.md).
//
//go:embed exemplars/default.jsonl
var defaultExemplars []byte

// DefaultExemplars parses the built-in exemplar set.
func DefaultExemplars() ([]Exemplar, error) {
	return ParseExemplars(defaultExemplars)
}

// ParseExemplars reads JSON lines of Exemplar.
func ParseExemplars(data []byte) ([]Exemplar, error) {
	var out []Exemplar
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var x Exemplar
		if err := json.Unmarshal(line, &x); err != nil {
			return nil, fmt.Errorf("exemplars line %d: %w", n, err)
		}
		if x.Label != LabelBlock && x.Label != LabelAllow {
			return nil, fmt.Errorf("exemplars line %d: label %q", n, x.Label)
		}
		out = append(out, x)
	}
	return out, sc.Err()
}

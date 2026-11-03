// Package evalset loads the EN/VI prompt-injection eval set (eval/data), runs
// it through the gateway input pipeline and computes detection metrics.
package evalset

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Row is one line of an eval/data/*.jsonl file.
type Row struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    string `json:"label"` // "attack" | "benign"
	Category string `json:"category"`
	Lang     string `json:"lang"`    // "en" | "vi"
	Variant  string `json:"variant"` // orig | no_diacritics | teencode | leet | translated
	Source   string `json:"source"`
	License  string `json:"license"`
}

// IsAttack reports whether the row is a positive.
func (r Row) IsAttack() bool { return r.Label == "attack" }

// Load reads every *.jsonl file in dir, in name order.
func Load(dir string) ([]Row, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .jsonl files in %s", dir)
	}
	sort.Strings(files)
	var rows []Row
	for _, f := range files {
		rs, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		rows = append(rows, rs...)
	}
	return rows, nil
}

func loadFile(path string) ([]Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []Row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if r.Label != "attack" && r.Label != "benign" {
			return nil, fmt.Errorf("%s:%d: bad label %q", path, n, r.Label)
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

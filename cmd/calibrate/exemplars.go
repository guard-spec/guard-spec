package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"unicode/utf8"

	"github.com/promptshield/promptshield/internal/inference/ml"
)

// trainRow is one line of train/data/*.jsonl.
type trainRow struct {
	ID      string   `json:"id"`
	Text    string   `json:"text"`
	Labels  []string `json:"labels"`
	Lang    string   `json:"lang"`
	Variant string   `json:"variant"`
	Source  string   `json:"source"`
	License string   `json:"license"`
	Group   string   `json:"group"`
}

func (r trainRow) attack() bool { return len(r.Labels) != 1 || r.Labels[0] != "benign" }

func readTrain(path string) ([]trainRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []trainRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for sc.Scan() {
		var r trainRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// selectExemplars picks, per language and attack category, perCat attacks and,
// per language, benignPerLang benign rows. Within a cell rows are sorted by id
// (a content hash), one row per generation group is kept so that templates
// are not repeated, and rows are taken at even steps through the list.
// Very short and very long texts are skipped (long ones cost start-up time
// and match everything a little).
func selectExemplars(rows []trainRow, perCat, benignPerLang int) []ml.Exemplar {
	cells := map[string][]trainRow{}
	for _, r := range rows {
		n := utf8.RuneCountInString(r.Text)
		if n < 15 || n > 500 {
			continue
		}
		key := r.Lang + "/benign"
		if r.attack() {
			key = r.Lang + "/" + r.Labels[0]
		}
		cells[key] = append(cells[key], r)
	}
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []ml.Exemplar
	for _, k := range keys {
		rs := cells[k]
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
		seen := map[string]bool{}
		var uniq []trainRow
		for _, r := range rs {
			g := r.Group
			if g == "" {
				g = r.ID
			}
			if !seen[g] {
				seen[g] = true
				uniq = append(uniq, r)
			}
		}
		n := perCat
		if !uniq[0].attack() {
			n = benignPerLang
		}
		n = min(n, len(uniq))
		for i := 0; i < n; i++ {
			r := uniq[i*len(uniq)/n]
			x := ml.Exemplar{ID: r.ID, Text: r.Text, Lang: r.Lang, Source: r.Source, License: r.License, Label: ml.LabelAllow}
			if r.attack() {
				x.Label, x.Category = ml.LabelBlock, r.Labels[0]
			}
			out = append(out, x)
		}
	}
	return out
}

func runExemplars(args []string) int {
	fs := flag.NewFlagSet("exemplars", flag.ContinueOnError)
	train := fs.String("train", "train/data/train.jsonl", "training split to pick from (never eval/ or the validation split)")
	out := fs.String("out", "internal/inference/ml/exemplars/default.jsonl", "output file")
	perCat := fs.Int("per-category", 20, "attacks per language and category")
	benign := fs.Int("benign-per-lang", 120, "benign exemplars per language")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rows, err := readTrain(*train)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 2
	}
	ex := selectExemplars(rows, *perCat, *benign)
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	counts := map[string]int{}
	for _, x := range ex {
		if err := enc.Encode(x); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		counts[x.Lang+"/"+x.Label]++
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("wrote %d exemplars to %s: %v\n", len(ex), *out, counts)
	return 0
}

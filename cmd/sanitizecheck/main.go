// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Command sanitizecheck runs the input sanitizer over JSONL corpora and
// reports what it does to each text: how many bytes it removes, which texts it
// truncates (more than -min-loss of their bytes removed) and which it rejects.
// It reads only the files it is given and prints no text, only ids, sizes and
// the fields id, source, genre, lang and kind/label when present.
//
//	go run ./cmd/sanitizecheck -json out.json eval/data/en.jsonl eval/data/vi.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

type row struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Source string `json:"source"`
	Genre  string `json:"genre"`
	Lang   string `json:"lang"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
}

// rawTag matches a mention of an element whose content an HTML parser treats
// as raw text (or drops): the cause this tool looks for.
var rawTag = regexp.MustCompile(`(?i)<\s*/?\s*(script|style|textarea|plaintext|xmp|noscript|iframe|noembed|noframes|title)\b`)

type hit struct {
	File     string  `json:"file"`
	ID       string  `json:"id"`
	Source   string  `json:"source,omitempty"`
	Genre    string  `json:"genre,omitempty"`
	Lang     string  `json:"lang,omitempty"`
	Class    string  `json:"class,omitempty"`
	InBytes  int     `json:"in_bytes"`
	OutBytes int     `json:"out_bytes"`
	LossFrac float64 `json:"loss_frac"`
	RawTags  int     `json:"raw_tag_mentions"`
	Rejected string  `json:"rejected,omitempty"`
}

type fileStats struct {
	File         string `json:"file"`
	Texts        int    `json:"texts"`
	InBytes      int64  `json:"in_bytes"`
	RemovedBytes int64  `json:"removed_bytes"`
	WithRawTag   int    `json:"with_raw_tag_mention"`
	Truncated    int    `json:"truncated"`
	Rejected     int    `json:"rejected"`
}

func main() {
	minLoss := flag.Float64("min-loss", 0.01, "a text counts as truncated when more than this fraction of its bytes is removed")
	jsonOut := flag.String("json", "", "write the per-file stats and every truncated or rejected text (ids only) here")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: sanitizecheck [-min-loss f] [-json out] file.jsonl...")
		os.Exit(2)
	}
	var stats []fileStats
	var hits []hit
	for _, f := range flag.Args() {
		s, h, err := check(f, *minLoss)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		stats = append(stats, s)
		hits = append(hits, h...)
	}
	fmt.Printf("| file | texts | removed bytes | with a raw-text tag | truncated (> %.0f%%) | rejected |\n|---|---|---|---|---|---|\n", *minLoss*100)
	for _, s := range stats {
		fmt.Printf("| %s | %d | %d (%.2f%%) | %d | %d | %d |\n", s.File, s.Texts, s.RemovedBytes,
			100*float64(s.RemovedBytes)/float64(max(s.InBytes, 1)), s.WithRawTag, s.Truncated, s.Rejected)
	}
	// Truncated and rejected texts by source and genre.
	by := map[string][2]int{}
	for _, h := range hits {
		k := h.Source + " / " + h.Genre
		v := by[k]
		if h.Rejected != "" {
			v[1]++
		} else {
			v[0]++
		}
		by[k] = v
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		fmt.Printf("\n| source / genre | truncated | rejected |\n|---|---|---|\n")
		for _, k := range keys {
			fmt.Printf("| %s | %d | %d |\n", k, by[k][0], by[k][1])
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(map[string]any{"min_loss": *minLoss, "files": stats, "texts": hits}, "", " ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func check(path string, minLoss float64) (fileStats, []hit, error) {
	st := fileStats{File: path}
	f, err := os.Open(path)
	if err != nil {
		return st, nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var hits []hit
	for {
		line, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			var x row
			if jerr := json.Unmarshal(line, &x); jerr != nil {
				return st, nil, fmt.Errorf("%s: %w", path, jerr)
			}
			st.Texts++
			st.InBytes += int64(len(x.Text))
			tags := len(rawTag.FindAllStringIndex(x.Text, -1))
			if tags > 0 {
				st.WithRawTag++
			}
			out, _, serr := sanitizer.Sanitize(x.Text)
			h := hit{File: path, ID: x.ID, Source: x.Source, Genre: x.Genre, Lang: x.Lang, Class: x.Kind + x.Label,
				InBytes: len(x.Text), OutBytes: len(out), RawTags: tags}
			switch {
			case serr != nil:
				st.Rejected++
				h.Rejected = serr.Error()
				h.OutBytes = 0
				hits = append(hits, h)
			default:
				st.RemovedBytes += int64(len(x.Text) - len(out))
				h.LossFrac = float64(len(x.Text)-len(out)) / float64(max(len(x.Text), 1))
				if h.LossFrac > minLoss {
					st.Truncated++
					hits = append(hits, h)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, nil, err
		}
	}
	return st, hits, nil
}

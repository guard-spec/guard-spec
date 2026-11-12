// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/inference/ml"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// The gateway's long path (MAX_SCAN_TOKENS, internal/inference/long.go and
// ml.ScoreLong), measured as it runs: the text is tokenized once and cut
// into the classifier's 256-token windows (64-token overlap), each window is
// fused from L1 on its text and L2 on its tokens (L3 left out, logreg l1,l2),
// and a document's windows get the gateway's adjustment for documents: the
// classifier's cap for untrusted content (-l2cap) and code corroboration
// (-corroboration). The long document rule of the classifier's calibration
// (ml.LongDocRule, calibration.json "long_doc"), when it has one and -longdoc
// is on, decides the document from its windows as the gateway does.
//
// This is the path a document of 100k tokens takes in the gateway: the
// fused 2,048-byte chunks of the other layers are the short path's units
// (texts up to 128 KiB of untrusted content), measured here without its cap.

const longLayer = "long"

// longDet is the long-path detector.
type longDet struct {
	stack  *ml.Stack
	fuser  *fusion.Fuser
	adjust inference.ChunkAdjust
	rule   *ml.LongDocRule // nil: the document's score is its largest window
}

func newLongDet(ctx context.Context, cfg ml.Config, useCap, corroborate, useRule bool) (*longDet, error) {
	lc := cfg
	var err error
	if lc.Layers, err = ml.ParseLayers("l1,l2"); err != nil {
		return nil, err
	}
	stack, err := ml.Build(ctx, lc, nil)
	if err != nil {
		return nil, err
	}
	if stack.Degraded() || stack.L2 == nil {
		_ = stack.Close()
		return nil, errors.New("long path: model layers unavailable:\n  " + strings.Join(stack.Problems, "\n  "))
	}
	sc := indirect.Scanner{NoCodeCorroboration: !corroborate}
	if useCap {
		sc.CapL2 = stack.UntrustedAdjust()
	}
	d := &longDet{stack: stack, fuser: stack.LongFuser(), adjust: sc.Adjust(indirect.SourceDocument)}
	if useRule {
		d.rule = stack.LongDocRule()
	}
	return d, nil
}

// docRule is d's rule as the long path takes it (a nil interface without one).
func (d *longDet) docRule() inference.LongDocRule {
	if d.rule == nil {
		return nil
	}
	return d.rule
}

// score returns the windows of text as the long path scores them (every
// window, no early exit), and the document's score under the long document
// rule (its largest window without one).
func (d *longDet) score(ctx context.Context, text string) ([]inference.LongWindow, float64, error) {
	res, _, err := ml.ScoreLong(ctx, d.fuser, d.stack.L2, []inference.LongInput{{Text: text, Adjust: d.adjust}},
		inference.LongOptions{KeepWindows: true, LongDoc: d.docRule()})
	if err != nil {
		return nil, 0, err
	}
	return res[0].Windows, float64(res[0].Score.Confidence), nil
}

// DumpWindow is one long-path window in the -dump file: its byte span, its
// score as the document sees it (after the cap and code corroboration), the
// calibrated L1 and L2 scores, the floor, and whether the L1 rules
// corroborate it (ml.L1Corroborates).
type DumpWindow struct {
	Start int     `json:"s"`
	End   int     `json:"e"`
	Score float64 `json:"p"`
	L1    float64 `json:"l1"`
	L2    float64 `json:"l2"`
	Floor float64 `json:"f,omitempty"`
	Corr  bool    `json:"c,omitempty"`
	Rules string  `json:"r,omitempty"` // the window's rules when it scores 0.5 or more
}

// DumpDoc is one document in the -dump file. Scores only, never text.
type DumpDoc struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Lang      string   `json:"lang"`
	Genre     string   `json:"genre"`
	Split     string   `json:"split"`
	Tokens    int      `json:"tokens"`
	Scored    int      `json:"scored_tokens"`
	Bytes     int      `json:"bytes"`
	Variant   string   `json:"variant,omitempty"`
	PayloadID string   `json:"payload_id,omitempty"`
	Host      string   `json:"host,omitempty"`
	Spans     [][2]int `json:"spans,omitempty"`
	Rejected  bool     `json:"rejected,omitempty"`
	// Intact is false when a payload span of an attack document is not in
	// the sanitized text whole (the sanitizer's HTML stripping took it).
	Intact *bool `json:"intact,omitempty"`
	// PayloadSpans are the spans in the sanitized text (-1 when not found).
	PayloadSpans [][2]int     `json:"payload_spans,omitempty"`
	Anomaly      float64      `json:"anomaly"`
	DocScore     float64      `json:"doc_score"` // the long path's document score (with the rule when on)
	Windows      []DumpWindow `json:"windows"`
}

// payloadSpans finds each span of d's payload in the sanitized text: the span
// sanitized alone, searched from the span's own offset backwards (the
// sanitizer only shortens a text). ok is false when one is missing.
func payloadSpans(d Doc, cleaned string) ([][2]int, bool) {
	var out [][2]int
	ok := true
	for _, sp := range d.Spans {
		if sp[0] < 0 || sp[1] > len(d.Text) || sp[0] >= sp[1] {
			return nil, false
		}
		p, _, err := sanitizer.Sanitize(d.Text[sp[0]:sp[1]])
		p = strings.TrimSpace(p)
		i := -1
		if err == nil && p != "" {
			i = strings.Index(cleaned[:min(len(cleaned), sp[1])], p)
			if i < 0 {
				i = strings.Index(cleaned, p)
			}
		}
		if i < 0 {
			ok = false
			out = append(out, [2]int{-1, -1})
			continue
		}
		out = append(out, [2]int{i, i + len(p)})
	}
	return out, ok
}

func dumpWindows(ws []inference.LongWindow) []DumpWindow {
	out := make([]DumpWindow, len(ws))
	for i, w := range ws {
		dw := DumpWindow{Start: w.Start, End: w.End, Score: float64(w.Score.Confidence)}
		if d := w.Score.Detail; d != nil {
			dw.L1, dw.L2, dw.Floor = d.L1, d.L2, d.Floor
			dw.Corr = ml.L1Corroborates(w.Score)
			if dw.Score >= 0.5 {
				dw.Rules = strings.Join(d.Rules, ",")
			}
		}
		out[i] = dw
	}
	return out
}

// dumper writes DumpDoc lines, gzipped, one file per split (dev and holdout
// apart, so that an analysis of the dev slice never reads the holdout one).
type dumper struct {
	mu    sync.Mutex
	files map[string]*os.File
	zw    map[string]*gzip.Writer
	enc   map[string]*json.Encoder
	base  string
}

func newDumper(base string) *dumper {
	return &dumper{base: base, files: map[string]*os.File{}, zw: map[string]*gzip.Writer{}, enc: map[string]*json.Encoder{}}
}

func (d *dumper) write(doc DumpDoc) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	enc, ok := d.enc[doc.Split]
	if !ok {
		p := fmt.Sprintf("%s-%s.jsonl.gz", d.base, doc.Split)
		f, err := os.Create(p)
		if err != nil {
			return err
		}
		zw := gzip.NewWriter(f)
		enc = json.NewEncoder(zw)
		d.files[doc.Split], d.zw[doc.Split], d.enc[doc.Split] = f, zw, enc
	}
	return enc.Encode(doc)
}

func (d *dumper) close() error {
	if d == nil {
		return nil
	}
	var errs []error
	for k, zw := range d.zw {
		errs = append(errs, zw.Close(), d.files[k].Close())
	}
	return errors.Join(errs...)
}

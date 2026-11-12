package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/guard-spec/guard-spec/internal/onnx"
)

func writeReport(rep *Report, out string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		return err
	}
	md := strings.TrimSuffix(out, ".json") + ".md"
	return os.WriteFile(md, []byte(markdown(rep)), 0o644)
}

func pct(v float64) string {
	if math.IsNaN(v) {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*v)
}

func f3(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "-"
	}
	return fmt.Sprintf("%.3f", v)
}

func f3p(v *float64) string {
	if v == nil {
		return "-"
	}
	return f3(*v)
}

func ptr(v float64) *float64 { return &v }

func markdown(rep *Report) string {
	var b strings.Builder
	h := rep.Header
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("## Long inputs: %s\n\n", h.Host)
	w("- Model: `%s` (SHA-256 `%.12s`), ONNX Runtime %s\n", h.Model, h.ModelSHA256, h.ORT)
	w("- CPU: %s, %d vCPU (%s/%s); INFERENCE_MAX_CONCURRENCY=%d, INFERENCE_INTRA_OP_THREADS=%q\n",
		h.CPU, h.VCPU, h.GOOS, h.GOARCH, h.MaxConcurrency, h.IntraOp)
	if p := h.Provider; p.Active == onnx.ProviderCUDA {
		w("- GPU: %s (CUDA device %d, driver %s, CUDA %s), ONNX Runtime CUDA execution provider; model file `%s`, INFERENCE_BATCH_SIZE=%d\n",
			p.GPU, p.DeviceID, p.Driver, p.CUDA, h.ModelFile, h.BatchSize)
	} else if h.ModelFile != "" {
		w("- Execution provider: %s; model file `%s`, INFERENCE_BATCH_SIZE=%d\n", p.Active, h.ModelFile, h.BatchSize)
	}
	w("- Commit: `%s`; date %s\n", h.Commit, h.Date)
	if h.Profile != "" {
		w("- Corpus: profile `%s`, %d documents, docs.jsonl SHA-256 `%.16s`\n", h.Profile, h.Docs, h.CorpusSHA256)
	}
	w("- Layers: %s; block threshold %.2f; classifier cap for untrusted content %s\n\n", strings.Join(h.Layers, ", "), h.Block,
		map[bool]string{true: "applied to the fused chunks", false: "none (no cap in the calibration, or -l2cap off)"}[h.L2Cap])

	p := rep.ScorePass
	w("### Score pass\n\n%d documents, %d tokens, %d L2 windows and %d fused chunks in %.0f s with %d documents at a time (%.0f tokens/s, %.0f CPU-s).\n\n",
		p.Docs, p.Tokens, p.Windows, p.Chunks, p.WallS, p.Workers, p.TokensPS, p.CPUS)

	if len(rep.Latency) > 0 {
		w("### Latency and CPU (one document at a time)\n\n")
		w("`l2` scores the whole text as batched 256-token windows; the fused rows score the gateway's 2048-byte chunks, K at a time. intra 0 is ONNX Runtime's default.\n\n")
		w("| Path | intra | K | ms/window | windows/s | tokens/s | CPU-s per 1k tokens | max tokens in 10 s |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, l := range rep.Latency {
			w("| %s | %d | %d | %.1f | %.1f | %.0f | %.3f | %d |\n", l.Path, l.Intra, l.K, l.MSPerWindow, l.WindowsPerS, l.TokensPerS, l.CPUSPer1kTok, l.Tokens10s)
		}
		w("\nWall time per document (ms):\n\n| Path | intra | K |")
		docs := rep.Latency[0].Docs
		for _, d := range docs {
			w(" %s (%dk tok) |", d.ID, (d.Tokens+500)/1000)
		}
		w("\n|---|---:|---:|%s\n", strings.Repeat("---:|", len(docs)))
		for _, l := range rep.Latency {
			w("| %s | %d | %d |", l.Path, l.Intra, l.K)
			for _, d := range l.Docs {
				w(" %.0f |", d.WallMS)
			}
			w("\n")
		}
		w("\n")
	}

	w("### Benign score distribution per unit\n\n| Layer | Lang | Genre | units | p50 | p90 | p99 | p99.9 | max | >= block |\n|---|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, q := range rep.Quantiles {
		w("| %s | %s | %s | %d | %s | %s | %s | %s | %s | %s |\n", q.Layer, q.Lang, q.Genre, q.N, f3(q.P50), f3(q.P90), f3(q.P99), f3(q.P999), f3(q.Max), pct(q.Above))
	}

	w("\n### Benign documents flagged at the block threshold, by size\n\n| Layer | Lang | Size | docs | mean units | FPR | gateway FPR |\n|---|---|---|---:|---:|---:|---:|\n")
	for _, r := range rep.DocFPR {
		w("| %s | %s | %s | %s | %.0f | %s | %s |\n", r.Layer, r.Lang, r.Size, docsLabel(r.Docs, r.Rejected), r.Units, pct(r.FPR), pct(r.Gateway))
	}

	w("\n### T(n): threshold for 1%% false positives over n units\n\n")
	w("FPR@block is the share of n-unit benign stretches whose maximum reaches %.2f. T is the larger of the bootstrap and GEV estimates.\n\n", h.Block)
	w("| Layer | Lang | units | n | FPR@block | bootstrap q99 | GEV q99 | Gumbel q99 | T(n) |\n|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, t := range rep.Thresholds {
		lang := t.Lang
		if t.Provisional {
			lang += " (provisional)"
		}
		for _, pt := range t.Points {
			short := ""
			if pt.Short {
				short = " *"
			}
			w("| %s | %s | %d | %d%s | %s | %s | %s | %s | %s |\n", t.Layer, lang, t.StreamUnits, pt.N, short, pct(pt.FPRBlock), f3(pt.Boot), f3p(pt.GEV), f3p(pt.Gumbel), f3(pt.T))
		}
	}
	w("\n\\* n is more than a fifth of the benign stream: a weak bootstrap estimate.\n")

	if len(rep.TPR) > 0 {
		w("\n### Attacks in long text: detection rate\n\n")
		w("At the block threshold, at T(n) for the document's own number of units, and as the gateway decides (score or sanitizer anomaly). `control` is the payload alone.\n\n")
		w("| Layer | Lang | Variant | docs | mean units | TPR@block | TPR@T(n) | gateway | hosts flagged |\n|---|---|---|---:|---:|---:|---:|---:|---:|\n")
		for _, r := range rep.TPR {
			w("| %s | %s | %s | %d | %.0f | %s | %s | %s | %d |\n", r.Layer, r.Lang, r.Variant, r.Docs, r.Units, pct(r.AtBlock), pct(r.AtTn), pct(r.Gateway), r.HostFlags)
		}
	}
	if len(rep.DocFPRSplit) > 0 || len(rep.TPRSplit) > 0 {
		w("\n### Dev and holdout slices\n\n")
		w("The tables above over the `split` of each document (bench/long/build.py: the last hex digit of a SHA-256 of the document id, or of the payload id for attacks, 0-7 dev and 8-f holdout). Tune on dev only; T(n) is the one of the whole benign stream.\n\n")
		if len(rep.DocFPRSplit) > 0 {
			w("| Split | Layer | Lang | Size | docs | mean units | FPR | gateway FPR |\n|---|---|---|---|---:|---:|---:|---:|\n")
			for _, r := range rep.DocFPRSplit {
				w("| %s | %s | %s | %s | %s | %.0f | %s | %s |\n", r.Split, r.Layer, r.Lang, r.Size, docsLabel(r.Docs, r.Rejected), r.Units, pct(r.FPR), pct(r.Gateway))
			}
		}
		if len(rep.TPRSplit) > 0 {
			w("\n| Split | Layer | Lang | Variant | docs | mean units | TPR@block | TPR@T(n) | gateway | hosts flagged |\n|---|---|---|---|---:|---:|---:|---:|---:|---:|\n")
			for _, r := range rep.TPRSplit {
				w("| %s | %s | %s | %s | %d | %.0f | %s | %s | %s | %d |\n", r.Split, r.Layer, r.Lang, r.Variant, r.Docs, r.Units, pct(r.AtBlock), pct(r.AtTn), pct(r.Gateway), r.HostFlags)
			}
		}
	}
	w("\n### Notes\n\n")
	for _, n := range rep.Notes {
		w("- %s\n", n)
	}
	return b.String()
}

// docsLabel is the document count of a false-positive row, with the number
// the sanitizer rejected before scoring when there is one ("33 (2 rejected)").
func docsLabel(docs, rejected int) string {
	if rejected == 0 {
		return fmt.Sprint(docs)
	}
	return fmt.Sprintf("%d (%d rejected)", docs, rejected)
}

// Command eval scores a prompt-injection detector on the EN/VI eval set.
//
//	go run ./cmd/eval [-data eval/data] [-detector regex] [-json out.json]
//	go run ./cmd/eval -baseline eval/baseline.json [-max-regression 0.02]
//
// Every row goes through the gateway's input path (sanitizer, then detector).
// With -baseline, the command exits 1 when any metric is worse than the
// baseline by more than -max-regression. Refresh the baseline with
// -json eval/baseline.json after an intended change.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/promptshield/promptshield/internal/evalset"
)

func main() {
	os.Exit(run())
}

func run() int {
	dataDir := flag.String("data", "eval/data", "directory with *.jsonl eval files")
	detName := flag.String("detector", "regex", "detector: "+strings.Join(evalset.DetectorNames(), ", "))
	jsonOut := flag.String("json", "", "write the report as JSON to this file")
	baseline := flag.String("baseline", "", "baseline report to compare against")
	maxReg := flag.Float64("max-regression", 0.02, "largest allowed drop (TPR, AUC) or rise (FPR) versus the baseline")
	flag.Parse()

	newDet, ok := evalset.Detectors[*detName]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown detector %q (have: %s)\n", *detName, strings.Join(evalset.DetectorNames(), ", "))
		return 2
	}
	det, err := newDet()
	if err != nil {
		fmt.Fprintln(os.Stderr, "detector:", err)
		return 2
	}
	rows, err := evalset.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		return 2
	}
	results, err := evalset.Run(context.Background(), rows, det)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}
	rep := evalset.BuildReport(*detName, results)
	rep.WriteTable(os.Stdout)

	if *jsonOut != "" {
		b, err := evalset.MarshalReport(rep)
		if err != nil {
			fmt.Fprintln(os.Stderr, "json:", err)
			return 2
		}
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "json:", err)
			return 2
		}
	}

	if *baseline != "" {
		b, err := os.ReadFile(*baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "baseline:", err)
			return 2
		}
		var base evalset.Report
		if err := json.Unmarshal(b, &base); err != nil {
			fmt.Fprintln(os.Stderr, "baseline:", err)
			return 2
		}
		if base.Detector != rep.Detector {
			fmt.Fprintf(os.Stderr, "baseline is for detector %q, not %q\n", base.Detector, rep.Detector)
			return 2
		}
		if regs := evalset.Compare(base, rep, *maxReg); len(regs) > 0 {
			fmt.Fprintf(os.Stderr, "\n%d regression(s) versus %s (max %.3f):\n", len(regs), *baseline, *maxReg)
			for _, r := range regs {
				fmt.Fprintln(os.Stderr, "  "+r)
			}
			return 1
		}
		fmt.Printf("\nno regression versus %s (max %.3f)\n", *baseline, *maxReg)
	}
	return 0
}

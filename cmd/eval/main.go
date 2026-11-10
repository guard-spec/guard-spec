// Command eval scores a prompt-injection detector on the EN/VI eval set.
//
//	go run ./cmd/eval [-data eval/data] [-detector fusion|l1|regex] [-json out.json] [-scores rows.jsonl]
//	go run ./cmd/eval -baseline eval/baseline.json [-max-regression 0.02]
//	go run ./cmd/eval -path tool [-corroboration on|off] [-l2cap on|off]
//	go run -tags onnx ./cmd/eval -detector fusion-ml [-layers l1,l2,l3] [-cascade] [-fusion logreg|max]
//
// Every row goes through the gateway's input path (sanitizer, then detector).
// With -path tool every row is treated as untrusted content instead: a tool
// definition row goes through the tools[] scan (detector plus MCP signals),
// any other row is scored as a tool result with the indirect category hint.
// -corroboration sets code corroboration on the tool path as
// TOOL_CODE_CORROBORATION does in the gateway (default: that variable, else
// on); with it off the report's detector name ends in /no-corroboration.
// -l2cap off leaves out the classifier's cap for untrusted content
// (calibration.json "l2_untrusted_max"); when a cap is in effect the name
// ends in /l2cap. With -baseline, the command exits 1 when any metric is
// worse than the baseline by more than -max-regression. Refresh the baseline
// with -json eval/baseline.json after an intended change.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/guard-spec/guard-spec/internal/evalset"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/inference"
)

func main() {
	os.Exit(run())
}

func run() int {
	dataDir := flag.String("data", "eval/data", "directory with *.jsonl eval files")
	detName := flag.String("detector", evalset.DefaultDetector, "detector: "+strings.Join(evalset.DetectorNames(), ", "))
	jsonOut := flag.String("json", "", "write the report as JSON to this file")
	scoresOut := flag.String("scores", "", "write per-row scores, gateway decisions and latencies as JSON lines to this file (bench/)")
	baseline := flag.String("baseline", "", "baseline report to compare against")
	maxReg := flag.Float64("max-regression", 0.02, "largest allowed drop (TPR, AUC) or rise (FPR) versus the baseline")
	path := flag.String("path", evalset.PathDirect, "input path: direct (user message) or tool (tool result / tool definition)")
	layers := flag.String("layers", "", "fusion-ml: layers to run (default $DETECTOR_LAYERS, else l1,l2,l3); implies -detector fusion-ml")
	cascade := flag.Bool("cascade", false, "fusion-ml: skip L2/L3 when L1 is decisive (DETECTOR_CASCADE)")
	fusionMethod := flag.String("fusion", "", "fusion-ml: logreg or max (default $DETECTOR_FUSION, else logreg)")
	corroboration := flag.String("corroboration", "", "-path tool: code corroboration on or off (default $TOOL_CODE_CORROBORATION, else on)")
	l2cap := flag.String("l2cap", "on", "-path tool: apply the classifier's cap for untrusted content (calibration.json l2_untrusted_max), on or off")
	flag.Parse()

	noCorroboration, err := parseCorroboration(*corroboration, os.Getenv("TOOL_CODE_CORROBORATION"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *path != evalset.PathTool {
		// Corroboration only applies to tool results and documents; the
		// variable alone does not stop a direct-path run.
		if noCorroboration && *corroboration != "" {
			fmt.Fprintln(os.Stderr, "-corroboration off needs -path tool (corroboration only applies to tool results and documents)")
			return 2
		}
		noCorroboration = false
	}
	useCap, err := parseOnOff("-l2cap", *l2cap)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var (
		det   evalset.Detector
		capL2 inference.ChunkAdjust
	)
	if *detName == mlDetector || *layers != "" {
		var name string
		det, capL2, name, err = newMLDetector(*layers, *cascade, *fusionMethod)
		if err != nil {
			fmt.Fprintln(os.Stderr, "detector:", err)
			return 2
		}
		*detName = name
	} else {
		newDet, ok := evalset.Detectors[*detName]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown detector %q (have: %s, %s)\n", *detName, strings.Join(evalset.DetectorNames(), ", "), mlDetector)
			return 2
		}
		if det, err = newDet(); err != nil {
			fmt.Fprintln(os.Stderr, "detector:", err)
			return 2
		}
	}
	rows, err := evalset.Load(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		return 2
	}
	var results []evalset.Result
	name := *detName
	switch *path {
	case evalset.PathDirect:
		results, err = evalset.Run(context.Background(), rows, det)
	case evalset.PathTool:
		rd, ok := det.(evalset.RunnerDetector)
		if !ok {
			fmt.Fprintf(os.Stderr, "detector %q has no runner for -path tool\n", *detName)
			return 2
		}
		scanner := indirect.Scanner{Runner: rd.Runner, NoCodeCorroboration: noCorroboration}
		if useCap {
			scanner.CapL2 = capL2
		}
		results, err = evalset.RunIndirectWith(context.Background(), rows, scanner)
		name += toolPathName(noCorroboration, scanner.CapL2 != nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown path %q (have: direct, tool)\n", *path)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}
	rep := evalset.BuildReport(name, results)
	rep.WriteTable(os.Stdout)

	if *scoresOut != "" {
		if err := writeScores(*scoresOut, results); err != nil {
			fmt.Fprintln(os.Stderr, "scores:", err)
			return 2
		}
	}

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

// toolPathName is the suffix of the detector name on the tool path: the
// path, then /no-corroboration and /l2cap when they apply, so a baseline is
// only compared with the same configuration.
func toolPathName(noCorroboration, capped bool) string {
	name := "/" + evalset.PathTool
	if noCorroboration {
		name += "/no-corroboration"
	}
	if capped {
		name += "/l2cap"
	}
	return name
}

// parseCorroboration reads -corroboration, falling back to the gateway's
// TOOL_CODE_CORROBORATION; it reports whether corroboration is off.
func parseCorroboration(flagVal, envVal string) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(flagVal))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(envVal))
	}
	switch v {
	case "", "on":
		return false, nil
	case "off":
		return true, nil
	}
	return false, fmt.Errorf("-corroboration (or TOOL_CODE_CORROBORATION) must be on or off, not %q", v)
}

// parseOnOff reads an on|off flag (on when empty).
func parseOnOff(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%s must be on or off, not %q", name, v)
}

func writeScores(path string, results []evalset.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := evalset.WriteScores(f, results); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

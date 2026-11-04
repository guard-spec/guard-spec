// Command calibrate prepares the model layers of the detector (L2, L3) on the
// classifier's validation split. It never reads eval/.
//
//	go run ./cmd/calibrate exemplars            # pick the L3 exemplar set from train/data/train.jsonl
//	go run -tags onnx ./cmd/calibrate fit       # fit L2/L3 Platt scaling and compare fusion methods
//	go run -tags onnx ./cmd/calibrate fit -write  # also store calibration.json next to the classifier
//
// fit scores every row of the validation splits (train/data/val.jsonl, val_hard.jsonl, val_vi_variants.jsonl and
// val_v3.jsonl; never val_v3_holdout.jsonl) with L1, L2 and L3 (after the
// gateway's sanitizer), fits the L2 and L3 Platt scaling on all of it, and
// compares "max of calibrated layers" with a logistic regression over the
// calibrated logits by k-fold cross-validation on the same split (calibration
// and regression refitted on the training folds, scored on the held-out fold).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: calibrate exemplars|fit [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "exemplars":
		os.Exit(runExemplars(os.Args[2:]))
	case "fit":
		os.Exit(runFit(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (have exemplars, fit)\n", os.Args[1])
		os.Exit(2)
	}
}

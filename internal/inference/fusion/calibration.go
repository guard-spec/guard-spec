package fusion

// DefaultL1Calibration is FitPlatt over the L1 rule scores of
// testdata/calibration.jsonl (sanitized first, as in the gateway).
// TestL1CalibrationIsFitted refits it and fails when the rules or the
// calibration split change without updating these numbers.
var DefaultL1Calibration = Calibration{A: 0.998, B: 0.356}

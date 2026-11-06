package evalset

import (
	"bufio"
	"encoding/json"
	"io"
)

// RowScore is one line of the per-row score file (cmd/eval -scores): what an
// external harness (bench/) needs to compute its own metrics without
// re-implementing the gateway's input path.
type RowScore struct {
	ID        string  `json:"id"`
	Label     string  `json:"label"`
	Lang      string  `json:"lang"`
	Score     float64 `json:"score"`   // detector score; 1 when rejected
	Anomaly   float64 `json:"anomaly"` // sanitizer anomaly score
	Rejected  bool    `json:"rejected"`
	Blocked   bool    `json:"blocked"` // the gateway's /v1/scan decision (GatewayBlocks)
	LatencyUS float64 `json:"latency_us"`
}

// WriteScores writes one JSON object per result, in input order.
func WriteScores(w io.Writer, results []Result) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for _, r := range results {
		if err := enc.Encode(RowScore{
			ID: r.Row.ID, Label: r.Row.Label, Lang: r.Row.Lang,
			Score: r.Score, Anomaly: r.Anomaly, Rejected: r.Rejected, Blocked: r.GatewayBlocks(),
			LatencyUS: float64(r.Latency.Nanoseconds()) / 1e3,
		}); err != nil {
			return err
		}
	}
	return bw.Flush()
}

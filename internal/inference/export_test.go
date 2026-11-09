package inference

import "context"

// ScanSequential is Scan's injection score as it was computed before the
// short path ran chunks in parallel: one chunk after the other, no dedupe.
// The identity tests compare Scan against it.
func ScanSequential(ctx context.Context, m ModelBackend, text string) (Score, error) {
	chunks, err := chunkText(text, 512, 448)
	if err != nil {
		return Score{}, err
	}
	s, err := runChunked(ctx, m, chunks)
	if err != nil {
		return Score{}, err
	}
	return maxScore(s), nil
}

// ScanUncappedSequential is ScanSequential without the 16-chunk cap: what
// scanning a long text the short path's way would cost (benchmarks only).
func ScanUncappedSequential(ctx context.Context, m ModelBackend, text string) (Score, error) {
	s, err := runChunked(ctx, m, chunkAll(text, shortWindowChars, shortStrideChars))
	if err != nil {
		return Score{}, err
	}
	return maxScore(s), nil
}

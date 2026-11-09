package main

import "unicode/utf8"

// The gateway's fused scan path for a long untrusted text, reproduced here
// without its 16-chunk cap so that any length can be measured:
//
//   - cmd/gateway scoreSegments: segments of 24 KiB overlapping by 1 KiB;
//   - internal/inference chunkText: in each segment, chunks of 2048 bytes
//     (512 "tokens" of 4 bytes) every 1792 bytes, each scored by the fused
//     detector (L1 rules, L2 on the chunk's own 256-token windows, ...).
//
// Keep these in step with those two functions; they are copied rather than
// called so that the benchmark does not change the gateway's code paths.
const (
	segmentBytes   = 24 << 10
	segmentOverlap = 1 << 10
	chunkBytes     = 512 * 4
	chunkStride    = 448 * 4
)

// span is a byte range [start, end) of a text.
type span struct{ start, end int }

// segmentSpans cuts text like cmd/gateway scoreSegments.
func segmentSpans(text string) []span {
	if len(text) <= segmentBytes {
		return []span{{0, len(text)}}
	}
	var out []span
	for start := 0; start < len(text); {
		end := min(start+segmentBytes, len(text))
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end--
		}
		out = append(out, span{start, end})
		if end == len(text) {
			break
		}
		next := end - segmentOverlap
		for next > start && !utf8.RuneStart(text[next]) {
			next--
		}
		start = next
	}
	return out
}

// chunkSpans cuts text like internal/inference chunkText, with no cap.
func chunkSpans(text string) []span {
	if len(text) <= chunkBytes {
		return []span{{0, len(text)}}
	}
	var out []span
	for start := 0; ; start = runeStart(text, start+chunkStride) {
		end := runeStart(text, min(start+chunkBytes, len(text)))
		out = append(out, span{start, end})
		if end == len(text) {
			return out
		}
	}
}

func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// fusedUnits are the chunks the gateway scores for an untrusted text, in
// order, as byte ranges of the whole text.
func fusedUnits(text string) []span {
	var out []span
	for _, seg := range segmentSpans(text) {
		for _, c := range chunkSpans(text[seg.start:seg.end]) {
			out = append(out, span{seg.start + c.start, seg.start + c.end})
		}
	}
	return out
}

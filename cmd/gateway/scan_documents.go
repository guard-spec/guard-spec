package main

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/promptshield/promptshield/internal/indirect"
	"github.com/promptshield/promptshield/internal/inference"
	"github.com/promptshield/promptshield/internal/sanitizer"
)

// maxScanDocuments bounds the documents of one /guardrail/scan request.
const maxScanDocuments = 64

// documentSources are the accepted values of documents[].source.
var documentSources = map[string]bool{"web": true, "email": true, "file": true, "tool": true, "other": true}

// scanDocument is one entry of documents[] in a /guardrail/scan request.
type scanDocument struct {
	ID      string `json:"id"`
	Source  string `json:"source"` // web, email, file, tool or other (the default)
	Content string `json:"content"`
}

// documentResult is the verdict on one document.
type documentResult struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	InjectionScore   float64  `json:"injection_score"`
	Category         string   `json:"category,omitempty"`
	DetectorCategory string   `json:"detector_category,omitempty"`
	Rules            []string `json:"rules,omitempty"`
	AnomalyScore     float32  `json:"anomaly_score"`
	Blocked          bool     `json:"blocked"`
	Verdict          string   `json:"verdict"` // allow or block
}

func verdictName(blocked bool) string {
	if blocked {
		return actionBlock
	}
	return actionAllow
}

// baseScanConfig is the gateway's scan configuration without org overrides.
func (gw gateway) baseScanConfig() scanConfig {
	if gw.scan != nil {
		return *gw.scan
	}
	return defaultScanConfig()
}

// scanHandler classifies text without calling a model. The request carries
// "text" (the user's input, as before), "documents" (third-party content,
// classified one by one as indirect injection), or both. The response keeps
// the fields it always had for text; "blocked" and "verdict" cover everything.
func scanHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		release := gw.audit.hold()
		defer release()
		var req struct {
			Text      string         `json:"text"`
			Documents []scanDocument `json:"documents"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if req.Text == "" && len(req.Documents) == 0 {
			return c.Status(400).JSON(fiber.Map{"error": "text or documents is required"})
		}
		if len(req.Documents) > maxScanDocuments {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("at most %d documents", maxScanDocuments)})
		}
		total := 0
		for i := range req.Documents {
			d := &req.Documents[i]
			if d.Source == "" {
				d.Source = "other"
			}
			if !documentSources[d.Source] {
				return c.Status(400).JSON(fiber.Map{"error": "documents[].source must be web, email, file, tool or other"})
			}
			if d.Content == "" {
				return c.Status(400).JSON(fiber.Map{"error": "documents[].content is required"})
			}
			total += len(d.Content)
		}
		if total > maxUntrustedBytes {
			return scanError(c, errDocumentsTooLong)
		}

		entry := newEntry(c)
		gw := gw.forOrg(entry.OrgID)
		resp := fiber.Map{}
		blocked := false
		var direct float64

		if req.Text != "" {
			cleaned, report, err := sanitizer.Sanitize(req.Text)
			if err != nil {
				return c.Status(422).JSON(fiber.Map{"error": err.Error()})
			}
			scores, err := gw.runner.Scan(gw.base, cleaned)
			if err != nil {
				return scanError(c, err)
			}
			blocked = scores.Injection.Confidence >= injectionBlockThreshold ||
				report.AnomalyScore >= anomalyBlockThreshold
			entry.Scores, entry.Report, entry.SourceRole = scores, report, string(indirect.SourceUser)
			direct = float64(scores.Injection.Confidence)
			resp = fiber.Map{
				"injection_score": scores.Injection.Confidence,
				"injection_label": scores.Injection.Label,
				"toxicity_score":  scores.Toxicity.Confidence,
				"anomaly_score":   report.AnomalyScore,
				"had_tag_chars":   report.HadTagChars,
				"had_bidi":        report.HadBidi,
				"bytes_removed":   report.BytesRemoved,
				"sanitized_text":  cleaned,
			}
		}

		if len(req.Documents) > 0 {
			threshold := gw.baseScanConfig().IndirectThreshold
			scanner := indirect.Scanner{Runner: gw.runner}
			results := make([]documentResult, 0, len(req.Documents))
			for _, d := range req.Documents {
				cleaned, report, err := sanitizer.Sanitize(d.Content)
				if err != nil {
					return c.Status(422).JSON(fiber.Map{"error": fmt.Sprintf("document %q: %v", d.ID, err)})
				}
				src := indirect.SourceDocument
				if d.Source == "tool" {
					src = indirect.SourceTool
				}
				v, err := scanner.Score(gw.base, cleaned, src)
				if err != nil {
					return scanError(c, err)
				}
				docBlocked := v.Score >= threshold || report.AnomalyScore >= anomalyBlockThreshold
				blocked = blocked || docBlocked
				results = append(results, documentResult{
					ID: d.ID, Source: d.Source, InjectionScore: v.Score,
					Category: v.Category, DetectorCategory: v.DetectorCategory, Rules: v.Rules,
					AnomalyScore: report.AnomalyScore, Blocked: docBlocked, Verdict: verdictName(docBlocked),
				})
				entry.Report = worseReport(entry.Report, report)
				if entry.Indirect.Source == "" || v.Score > entry.Indirect.Score {
					entry.Indirect = v
				}
			}
			resp["documents"] = results
			if req.Text == "" || entry.Indirect.Score > direct {
				entry.Scores, entry.SourceRole = verdictScores(entry.Indirect), string(entry.Indirect.Source)
			}
		}

		resp["blocked"] = blocked
		resp["verdict"] = verdictName(blocked)
		entry.Action = verdictName(blocked)
		entry.LatencyMs = int(time.Since(start).Milliseconds())
		gw.audit.record(entry)
		return c.JSON(resp)
	}
}

// errDocumentsTooLong maps to 413 through scanError.
var errDocumentsTooLong = fmt.Errorf("documents exceed %d bytes: %w", maxUntrustedBytes, inference.ErrInputTooLong)

// worseReport keeps the strongest sanitizer signals of two reports.
func worseReport(a, b sanitizer.Report) sanitizer.Report {
	var g textGuard
	g.report = a
	g.merge(b)
	return g.report
}

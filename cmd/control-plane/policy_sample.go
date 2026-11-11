// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"sync"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/inference/fusion"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/sanitizer"
)

// A sample sentence for the policy editor's simulator (RF-a1dbafea U3):
//
//	POST /policy/sample {"text": "..."}
//
// scores the text the way the gateway's first steps do, with what runs
// without model files: the sanitizer (anomaly.*), the L1 rules (scores.l1,
// and injection.score as the L1-only fusion gives it) and the personal data
// patterns (input.pii.*). It answers the rule fields; the editor sends them
// to POST .../policies/simulate, the existing simulator, to show which rules
// match. L2 and L3 need the gateway's models: scores.l2 and scores.l3 are -1
// (did not run), as on a gateway without them, so a rule on them, or an
// injection score the classifier would raise, is not reproduced here.
//
// Nothing is stored or logged; the text is the user's own sample.

// maxSampleBytes bounds a sample.
const maxSampleBytes = 8000

type sampleAnswer struct {
	// Vars are rule fields by name, for the simulator's vars.
	Vars map[string]any `json:"vars"`
	// Layers that scored the text: always ["l1"].
	Layers []string `json:"layers"`
	// Rules are the ids of the L1 rules and categories that fired.
	Rules []string `json:"rules"`
}

var (
	sampleFuserOnce sync.Once
	sampleFuser     *fusion.Fuser
)

// scoreSample scores text with the sanitizer, L1 and the PII patterns.
func scoreSample(ctx context.Context, text string) (sampleAnswer, error) {
	sampleFuserOnce.Do(func() { sampleFuser = fusion.New() })
	clean, rep, err := sanitizer.Sanitize(text)
	if err != nil {
		return sampleAnswer{}, err
	}
	res := sampleFuser.Score(ctx, clean)
	label := "BENIGN"
	if res.Category != "" {
		label = res.Category
	}
	counts := outputguard.CountPII(clean)
	kinds := []string{}
	for _, k := range outputguard.PIIKinds {
		if counts[k] > 0 {
			kinds = append(kinds, k)
		}
	}
	rules := res.Rules
	if rules == nil {
		rules = []string{}
	}
	return sampleAnswer{
		Vars: map[string]any{
			"injection.score":       res.Score,
			"injection.label":       label,
			"injection.category":    res.Category,
			"injection.source_role": "user",
			"scores.l1":             res.Layers[fusion.L1],
			"scores.l2":             fusion.Missing,
			"scores.l3":             fusion.Missing,
			"anomaly.score":         float64(rep.AnomalyScore),
			"anomaly.has_tag_chars": rep.HadTagChars,
			"anomaly.has_bidi":      rep.HadBidi,
			"input.pii.kinds":       kinds,
			"input.pii.count":       counts.Total(),
		},
		Layers: []string{"l1"},
		Rules:  rules,
	}, nil
}

func samplePolicyVars() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Text *string `json:"text"`
		}
		if err := json.Unmarshal(c.Body(), &req); err != nil || req.Text == nil {
			return c.Status(400).JSON(fiber.Map{"error": "text is required"})
		}
		if len(*req.Text) > maxSampleBytes {
			return c.Status(400).JSON(fiber.Map{"error": "the sample is longer than 8000 bytes"})
		}
		if !utf8.ValidString(*req.Text) {
			return c.Status(400).JSON(fiber.Map{"error": "the sample is not valid UTF-8"})
		}
		out, err := scoreSample(c.Context(), *req.Text)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(out)
	}
}

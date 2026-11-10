package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/indirect"
)

// maxScanTools bounds the tools of one /guardrail/scan/tools request.
const maxScanTools = 256

// mcpTool is a tool as an MCP server lists it (tools/list).
type mcpTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// toolResult is the verdict on one tool.
type toolResult struct {
	indirect.ToolVerdict
	Blocked bool   `json:"blocked"`
	Verdict string `json:"verdict"` // allow or block
}

// scanToolsHandler checks MCP tool definitions for poisoning before an agent
// loads them: each description and every description nested in inputSchema
// goes through the detector and CheckMCPDescription's signals. A tool is
// blocked when its score reaches the indirect floor.
func scanToolsHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		release := gw.audit.hold()
		defer release()
		var req struct {
			Tools []mcpTool `json:"tools"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if len(req.Tools) == 0 {
			return c.Status(400).JSON(fiber.Map{"error": "tools is required"})
		}
		if len(req.Tools) > maxScanTools {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("at most %d tools", maxScanTools)})
		}

		threshold := gw.baseScanConfig().IndirectThreshold
		scanner := indirect.Scanner{Runner: gw.runner, CapL2: gw.capL2}
		entry := newEntry(c)
		gw := gw.forRequest(&entry)
		results := make([]toolResult, 0, len(req.Tools))
		blocked := false
		var strongest indirect.Verdict
		for _, t := range req.Tools {
			tv, err := scanner.ScoreTool(gw.base,
				indirect.Tool{Name: t.Name, Description: t.Description, Schema: t.InputSchema}, "inputSchema", true)
			if errors.Is(err, indirect.ErrSchemaTooDeep) {
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("tool %q: %v", t.Name, err)})
			}
			if err != nil {
				return scanError(c, err)
			}
			toolBlocked := tv.Score >= threshold
			blocked = blocked || toolBlocked
			results = append(results, toolResult{ToolVerdict: tv, Blocked: toolBlocked, Verdict: verdictName(toolBlocked)})
			if strongest.Source == "" || tv.Score > strongest.Score {
				strongest = tv.Verdict
			}
		}

		entry.Indirect, entry.SourceRole = strongest, string(strongest.Source)
		entry.Scores = verdictScores(strongest)
		entry.Action = verdictName(blocked)
		if blocked {
			entry.Detected = layerScan
		}
		entry.LatencyMs = int(time.Since(start).Milliseconds())
		gw.audit.record(entry)
		return c.JSON(fiber.Map{"blocked": blocked, "verdict": verdictName(blocked), "tools": results})
	}
}

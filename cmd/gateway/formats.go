package main

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/indirect"
	"github.com/guard-spec/guard-spec/internal/outputguard"
	"github.com/guard-spec/guard-spec/internal/proxy"
)

// apiFormat is what differs between the request formats the gateway proxies:
// OpenAI chat and legacy completions, and the Anthropic Messages API. The
// pipeline (scan, thresholds, policies, routing, output guard, audit) is the
// same for all of them (proxyHandler).
type apiFormat struct {
	// path is the upstream path, appended to the upstream's base URL; also the
	// metric label of upstream calls.
	path string
	// guardBody sanitizes the untrusted text and collects what is classified.
	guardBody func(*textGuard, map[string]any) error
	// spotlight marks tool results for the model (SPOTLIGHT).
	spotlight func(map[string]any, indirect.Mode) (bool, error)
	// injectCanary puts the output guard's canary in the system prompt; false
	// when the body has nowhere to carry it.
	injectCanary func(map[string]any, string) bool
	// stub is the answer when no upstream is configured.
	stub func(model any) fiber.Map
	// call returns the request's own upstream settings, from its headers; nil
	// for none.
	call func(*fiber.Ctx) (proxy.Call, error)
	// checkRoute refuses an upstream that does not serve the format; nil
	// accepts any.
	checkRoute func(route) error
	// guardResponse runs the output guard on a whole response body.
	guardResponse func(*outputguard.Scanner, []byte, outputguard.Counts) ([]byte, error)
	// newStream returns the output guard of an event stream.
	newStream func(*outputguard.Scanner) streamGuard
	// streamError renders the event that ends a stream the gateway stopped.
	streamError func(message, errType, code string) []byte
	// history: the format follows SCAN_HISTORY and scores through the scan
	// cache (the Messages API, whose clients resend the whole session).
	history bool
}

// openAIFormat is chat completions (path /chat/completions) or legacy
// completions (/completions).
func openAIFormat(path string) apiFormat {
	return apiFormat{
		path:         path,
		guardBody:    (*textGuard).guardBody,
		spotlight:    spotlight,
		injectCanary: injectCanary,
		stub:         openAIStub,
		guardResponse: func(s *outputguard.Scanner, data []byte, counts outputguard.Counts) ([]byte, error) {
			return s.Response(data, counts)
		},
		newStream:   func(s *outputguard.Scanner) streamGuard { return s.NewEventStream() },
		streamError: openAIStreamError,
	}
}

func openAIStub(model any) fiber.Map {
	return fiber.Map{
		"id":     "chatcmpl-stub",
		"object": "chat.completion",
		"model":  model,
		"choices": []fiber.Map{{
			"message": fiber.Map{
				"role":    "assistant",
				"content": "[guardrail passed — configure UPSTREAM_LLM_URL to proxy to a real model]",
			},
			"finish_reason": "stop",
			"index":         0,
		}},
	}
}

// openAIStreamError is an error chunk. The blank lines first end any event
// the upstream left half-written, so the error is parsed as an event of its
// own rather than glued onto it.
func openAIStreamError(message, errType, code string) []byte {
	event, _ := json.Marshal(errorBody(message, errType, code))
	return append(append([]byte("\n\ndata: "), event...), '\n', '\n')
}

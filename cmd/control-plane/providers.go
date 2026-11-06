package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Model provider presets for the UI's catalog picker. The gateway speaks the
// OpenAI chat-completions format to every one of them for /v1/chat/completions:
// Anthropic and Gemini are reached through their OpenAI-compatible endpoints.
// An Anthropic upstream also serves the gateway's /v1/messages natively, at
// {base_url}/messages with the key as x-api-key.

type providerPreset struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name"`
	DefaultBaseURL  string   `json:"default_base_url"`
	KeyRequired     bool     `json:"key_required"`
	KeyEnvHint      string   `json:"key_env_hint"`
	NeedsAPIVersion bool     `json:"needs_api_version"`
	OpenAICompat    bool     `json:"openai_compatible_endpoint"` // the preset uses the provider's OpenAI-compatible API
	NativeMessages  bool     `json:"anthropic_messages"`         // the gateway's /v1/messages goes to it as is
	KnownModels     []string `json:"known_models"`
	DocsURL         string   `json:"docs_url"`
	Notes           string   `json:"notes"`
}

var providerCatalog = []providerPreset{
	{ID: "openai", DisplayName: "OpenAI", DefaultBaseURL: "https://api.openai.com/v1", KeyRequired: true,
		KeyEnvHint: "UPSTREAM_KEY_OPENAI", KnownModels: []string{"gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini"},
		DocsURL: "https://platform.openai.com/docs/api-reference/chat"},
	{ID: "anthropic", DisplayName: "Anthropic", DefaultBaseURL: "https://api.anthropic.com/v1", KeyRequired: true,
		KeyEnvHint: "UPSTREAM_KEY_ANTHROPIC", OpenAICompat: true, NativeMessages: true,
		KnownModels: []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"},
		DocsURL:     "https://docs.claude.com/en/api/openai-sdk",
		Notes: "/v1/chat/completions uses Anthropic's OpenAI SDK compatibility endpoint; " +
			"/v1/messages (Claude Code) is sent to the Messages API as is."},
	{ID: "azure_openai", DisplayName: "Azure OpenAI", DefaultBaseURL: "https://<resource>.openai.azure.com/openai/v1",
		KeyRequired: true, KeyEnvHint: "UPSTREAM_KEY_AZURE_OPENAI", NeedsAPIVersion: true,
		DocsURL: "https://learn.microsoft.com/azure/ai-services/openai/reference",
		Notes:   "The key is sent in the api-key header; api_version is added to every request."},
	{ID: "gemini", DisplayName: "Google Gemini", DefaultBaseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
		KeyRequired: true, KeyEnvHint: "UPSTREAM_KEY_GEMINI", OpenAICompat: true,
		KnownModels: []string{"gemini-2.5-pro", "gemini-2.5-flash"},
		DocsURL:     "https://ai.google.dev/gemini-api/docs/openai",
		Notes:       "Uses Gemini's OpenAI compatibility endpoint."},
	{ID: "ollama", DisplayName: "Ollama", DefaultBaseURL: "http://localhost:11434/v1",
		KnownModels: []string{"llama3.1", "qwen2.5", "mistral"},
		DocsURL:     "https://github.com/ollama/ollama/blob/main/docs/openai.md",
		Notes:       "A private address needs UPSTREAM_ALLOW_PRIVATE=true."},
	{ID: "vllm", DisplayName: "vLLM", DefaultBaseURL: "http://localhost:8000/v1", KeyEnvHint: "UPSTREAM_KEY_VLLM",
		DocsURL: "https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html",
		Notes:   "A private address needs UPSTREAM_ALLOW_PRIVATE=true."},
	{ID: "openai_compatible", DisplayName: "OpenAI-compatible", KeyEnvHint: "UPSTREAM_KEY_<NAME>",
		DocsURL: "https://platform.openai.com/docs/api-reference/chat"},
}

func providerCatalogHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"items": providerCatalog})
}

// probeTimeout bounds an upstream connection test.
const probeTimeout = 5 * time.Second

// wildcardKeyNote explains a test sent without the key.
const wildcardKeyNote = "the key was not sent: UPSTREAM_KEY_ORGS allows it to every organization (*), and a test " +
	"would let any org owner send it to an address of their choosing; list this organization's id for the key " +
	"to test with it"

// upstreamProxy builds the proxy the gateway would use for org's upstream u,
// with the same checks: base URL, UPSTREAM_KEY_ORGS, the key variable, and
// the dialer's refusal of private addresses unless UPSTREAM_ALLOW_PRIVATE.
//
// The key goes with the test only when UPSTREAM_KEY_ORGS names this org for
// it (or GUARD_ENV=dev): an org owner can point an upstream anywhere, and a
// key shared with every org through "*" must not be sent to a host they pick.
// keySent reports whether it is.
func upstreamProxy(u upstream, org uuid.UUID, s *appSettings) (px *proxy.Proxy, keySent bool, err error) {
	if err := proxy.ValidateBaseURL(u.BaseURL); err != nil {
		return nil, false, err
	}
	key := ""
	if u.APIKeyEnv != "" {
		if err := s.keyOrgs.Check(u.APIKeyEnv, org); err != nil {
			return nil, false, err
		}
		if !config.UpstreamKeyVarRe.MatchString(u.APIKeyEnv) {
			return nil, false, errors.New("api_key_env is not an UPSTREAM_KEY_ variable")
		}
		if s.keyOrgs.Explicit(u.APIKeyEnv, org) || config.DevMode() {
			getenv := s.getenv
			if getenv == nil {
				getenv = os.Getenv
			}
			if key = getenv(u.APIKeyEnv); key == "" {
				return nil, false, errors.New(u.APIKeyEnv + " is not set in the control plane's environment; " +
					"set the same UPSTREAM_KEY_* variables as the gateway to test connections")
			}
		}
	}
	keyHeader := ""
	headers := u.Headers
	switch u.Provider {
	case "azure_openai":
		keyHeader = "api-key"
	case "anthropic":
		// Anthropic's model list wants its own key header and a version, as
		// the gateway sends them for /v1/models and /v1/messages.
		keyHeader = "x-api-key"
		headers = map[string]string{"anthropic-version": "2023-06-01"}
		for k, v := range u.Headers {
			headers[k] = v
		}
	}
	px, err = proxy.New(proxy.Config{BaseURL: u.BaseURL, Key: key, KeyHeader: keyHeader, APIVersion: u.APIVersion,
		Headers: headers, Timeout: probeTimeout, DenyPrivate: !s.allowPrivate})
	return px, key != "", err
}

// testUpstream sends GET {base_url}/models and reports what came back. The
// answer holds model ids only, never the upstream's body.
func testUpstream(db *pgxpool.Pool, s *appSettings) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid upstream id"})
		}
		var u upstream
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			var err error
			u, err = scanUpstreamRow(tx.QueryRow(c.Context(), upstreamSelect+` WHERE id = $1 AND org_id = $2`, id, org))
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		if err != nil {
			return serverError(c, err)
		}
		px, keySent, err := upstreamProxy(u, org, s)
		if err != nil {
			return c.JSON(proxy.ProbeResult{Models: []string{}, Error: err.Error()})
		}
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		res := px.Probe(ctx)
		res.KeySent = keySent
		if u.APIKeyEnv != "" && !keySent {
			res.Note = wildcardKeyNote
		}
		logActivity(c, db, &org, "upstream.tested", u.Name,
			map[string]any{"ok": res.OK, "status": res.Status, "key_sent": keySent})
		return c.JSON(res)
	}
}

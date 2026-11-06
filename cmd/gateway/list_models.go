package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/proxy"
	"github.com/guard-spec/guard-spec/internal/tenant"
)

// modelsTimeout bounds the upstream call of GET /v1/models.
const modelsTimeout = 10 * time.Second

// modelsHandler answers GET /v1/models with the models of the key's default
// route (project, org, then UPSTREAM_LLM_URL): the upstream's allowed models
// when it has a list, its default model when it forces one, otherwise what
// the upstream's own GET {base_url}/models lists. Route rules are not
// followed: they depend on what a request contains. The answer is the OpenAI
// list, or the Anthropic one when the request has an anthropic-version header.
func modelsHandler(gw gateway) fiber.Handler {
	return func(c *fiber.Ctx) error {
		anthropic := c.Get("anthropic-version") != ""
		orgID, _ := tenant.OrgID(c)
		target, err := gw.resolveRoute(requestEntry{OrgID: orgID, ProjectID: tenant.ProjectID(c)}, policy.Decision{}, nil)
		if errors.Is(err, errRouteUnavailable) {
			return c.Status(fiber.StatusBadGateway).
				JSON(errorBody("route target unavailable", "server_error", "route_unavailable"))
		}
		if err != nil {
			slog.Error("upstreams unavailable", "org", orgID, "err", err)
			return policyUnavailable(c)
		}
		var ids []string
		switch {
		case len(target.models) > 0:
			ids = target.models
		case target.model != "":
			ids = []string{target.model}
		case target.proxy != nil:
			var call proxy.Call // OpenAI-compatible: the key as a bearer token
			if target.provider == providerAnthropic {
				if call, err = anthropicCall(c); err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(errorBody(err.Error(), "invalid_request_error", "invalid_header"))
				}
			}
			if ids, err = upstreamModels(gw.base, target, call); err != nil {
				return upstreamError(c, err)
			}
		}
		owner := target.name
		if owner == "" {
			owner = "guard-spec"
		}
		if anthropic {
			return c.JSON(anthropicModelList(ids))
		}
		return c.JSON(openAIModelList(ids, owner))
	}
}

// upstreamModels lists the upstream's models through GET {base_url}/models.
func upstreamModels(base context.Context, target route, call proxy.Call) ([]string, error) {
	ctx, cancel := context.WithTimeout(base, modelsTimeout)
	defer cancel()
	call.Method = http.MethodGet
	path := "/models"
	if target.provider == providerAnthropic {
		path = "/models?limit=1000" // Anthropic pages its list, 20 by default
	}
	resp, err := target.proxy.Do(ctx, path, nil, call)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	data, err := resp.ReadAll()
	if err != nil {
		return nil, err
	}
	return proxy.ModelIDs(data), nil
}

func openAIModelList(ids []string, owner string) fiber.Map {
	data := make([]fiber.Map, 0, len(ids))
	for _, id := range ids {
		data = append(data, fiber.Map{"id": id, "object": "model", "created": 0, "owned_by": owner})
	}
	return fiber.Map{"object": "list", "data": data}
}

// anthropicModelList is the shape of Anthropic's GET /v1/models, one page.
func anthropicModelList(ids []string) fiber.Map {
	data := make([]fiber.Map, 0, len(ids))
	for _, id := range ids {
		data = append(data, fiber.Map{"type": "model", "id": id, "display_name": displayName(id),
			"created_at": "1970-01-01T00:00:00Z"})
	}
	out := fiber.Map{"data": data, "has_more": false, "first_id": nil, "last_id": nil}
	if len(ids) > 0 {
		out["first_id"], out["last_id"] = ids[0], ids[len(ids)-1]
	}
	return out
}

// displayName is the id with its dashes as spaces: the upstream's own names
// are not kept, only ids.
func displayName(id string) string {
	return strings.ReplaceAll(id, "-", " ")
}

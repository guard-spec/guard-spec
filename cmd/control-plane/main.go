package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/guard-spec/guard-spec/internal/auth"
	"github.com/guard-spec/guard-spec/internal/config"
	"github.com/guard-spec/guard-spec/internal/datakey"
	"github.com/guard-spec/guard-spec/internal/metrics"
	"github.com/guard-spec/guard-spec/internal/policy"
	"github.com/guard-spec/guard-spec/internal/retention"
	secretsrc "github.com/guard-spec/guard-spec/internal/secrets"
	"github.com/guard-spec/guard-spec/internal/siem"
	"github.com/guard-spec/guard-spec/internal/tenant"
	"github.com/guard-spec/guard-spec/internal/version"
	"github.com/guard-spec/guard-spec/web"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultOrgID is the organization seeded by migration 002.
var defaultOrgID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if len(os.Args) > 1 && version.IsFlag(os.Args[1]) {
		fmt.Println("control-plane", version.String())
		return
	}

	// Handle "health" subcommand used by the Dockerfile HEALTHCHECK
	if len(os.Args) > 1 && os.Args[1] == "health" {
		resp, err := http.Get("http://localhost:8081/health")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if len(os.Args) > 1 && os.Args[1] == "audit" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		code := runAudit(ctx, os.Args[2:], os.Getenv, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		code := runKeys(ctx, os.Args[2:], os.Getenv, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}

	checkOnly := flag.Bool("check-policies", false,
		"validate every stored policy, list the failures and exit (1 if any fail); "+
			"DATABASE_URL must name a role that bypasses row-level security")
	flag.Parse()

	// PGPASSWORD_FILE or a vault: reference: pgx reads PGPASSWORD itself.
	if err := secretsrc.Export("PGPASSWORD"); err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	cfg := loadConfig()
	if *checkOnly {
		os.Exit(runPolicyCheck(context.Background(), cfg.DatabaseURL, os.Stdout))
	}
	if err := cfg.check(); err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ops, err := loadOpsConfig(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	keyOrgs, err := config.ParseKeyOrgs(os.Getenv("UPSTREAM_KEY_ORGS"))
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	secret := []byte(cfg.JWTSecret)
	mfaBox, err := auth.NewSecretBox(cfg.MFAEncKey)
	if err != nil && !errors.Is(err, auth.ErrNoMFAKey) {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	contentKeys, err := datakey.FromEnv(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	db, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		slog.Error("db connect", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(context.Background()); err != nil {
		slog.Error("db ping", "err", err)
		os.Exit(1)
	}

	if err := bootstrapAdmin(context.Background(), db, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		slog.Error("bootstrap admin", "err", err)
		os.Exit(1)
	}
	if err := checkMFAKey(context.Background(), db, mfaBox); err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	eng, err := policy.New()
	if err != nil {
		slog.Error("policy engine", "err", err)
		os.Exit(1)
	}

	// Mutual TLS to the gateway's admin listener (GATEWAY_TLS_*).
	gatewayClient, err := gatewayTLSClient(os.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	alertsCfg, err := loadAlertsConfig(secretsrc.Getenv)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var settings *appSettings
	app := newApp(db, secret, eng, cfg.AllowedOrigins, withEnvUpstream(cfg.UpstreamURL), withKeyOrgs(keyOrgs),
		func(s *appSettings) {
			s.mfaBox, s.publicURL, s.allowPrivate = mfaBox, cfg.PublicBaseURL, cfg.UpstreamAllowPrivate
			if contentKeys != nil {
				s.contentKeys = datakey.NewStore(contentKeys)
			}
			s.trustedProxies = cfg.TrustedProxies
			s.gatewayURL = cfg.GatewayURL
			s.gatewayClient = gatewayClient
			s.alertsBase = ctx
			s.alertsCfg = &alertsCfg
		},
		func(s *appSettings) { settings = s })
	rt := settings.alertsRT // built by newApp

	if err := metrics.Serve(ctx, ops.MetricsAddr); err != nil {
		slog.Error("metrics listener", "addr", ops.MetricsAddr, "err", err)
		os.Exit(1)
	}
	go retention.Run(ctx, db, ops.Retention)
	// Signed anchors of the activity log's hash chains (audit_chain.go).
	if k := secretsrc.Getenv("AUDIT_SIGNING_KEY"); k != "" {
		key, err := parseSigningKey(k)
		if err != nil {
			slog.Error("config", "err", err)
			os.Exit(1)
		}
		every := time.Hour
		if v := os.Getenv("AUDIT_ANCHOR_INTERVAL"); v != "" {
			if every, err = time.ParseDuration(v); err != nil || every < time.Minute {
				slog.Error("config", "err", "AUDIT_ANCHOR_INTERVAL must be a duration of at least 1m")
				os.Exit(1)
			}
		}
		go runAnchoring(ctx, db, key, every)
	} else {
		slog.Warn("AUDIT_SIGNING_KEY is not set: the activity log is hash-chained but its heads are not signed " +
			"(docs/security/README.md#audit-log-integrity)")
	}
	// The alert worker, the SSE hub and the Telegram polling fallback.
	alertsDone := make(chan struct{})
	go func() {
		defer close(alertsDone)
		rt.run(ctx)
	}()
	// SIEM export (internal/siem): due sinks every SIEM_EXPORT_INTERVAL (5s).
	siemEvery := 5 * time.Second
	if v := os.Getenv("SIEM_EXPORT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			siemEvery = d
		}
	}
	go siem.Run(ctx, db, newSIEMResolver(&alertsCfg), siemEvery)

	go func() {
		slog.Info("control-plane listening", "addr", cfg.ListenAddr, "version", version.String())
		if err := app.Listen(cfg.ListenAddr); err != nil {
			slog.Error("listen", "err", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = app.ShutdownWithTimeout(10 * time.Second)
	<-alertsDone
}

// appSettings are optional settings of newApp.
type appSettings struct {
	// envUpstreamURL is UPSTREAM_LLM_URL, for the simulator's env step.
	envUpstreamURL string
	ui             fs.FS // the admin UI; nil: web.Dist()
	// keyOrgs is UPSTREAM_KEY_ORGS: which orgs may name which UPSTREAM_KEY_*
	// variable as an upstream's api_key_env. The zero value allows none.
	keyOrgs config.KeyOrgs
	// mfaBox encrypts TOTP secrets (MFA_ENC_KEY); nil: 2FA cannot be set up.
	mfaBox *auth.SecretBox
	// contentKeys open the request content the gateway sealed (CONTENT_KEK,
	// CONTENT_KEK_FILE, CONTENT_KEK_VAULT_KEY); nil: sealed content is not shown.
	contentKeys *datakey.Store
	// publicURL is PUBLIC_BASE_URL, for SSO callback urls.
	publicURL string
	// allowPrivate is UPSTREAM_ALLOW_PRIVATE, for upstream connection tests.
	allowPrivate bool
	// For tests: the HTTP client of OIDC calls, a session lookup that needs
	// no database, and the environment upstream keys are read from.
	oidcClient    *http.Client
	sessionLookup auth.SessionLookup
	// trustedProxies is TRUSTED_PROXIES: whose X-Forwarded-For names the
	// client (clientip.go).
	trustedProxies []*net.IPNet
	getenv         func(string) string
	// Alerts (alerts.go): the configuration (nil: from the environment), the
	// context that ends SSE streams, whether the activity log emits no
	// events (tests), and the runtime newApp builds.
	alertsCfg     *alertsConfig
	alertsBase    context.Context
	noAlertEvents bool
	alertsRT      *alertsRuntime
	// gatewayURL is GATEWAY_URL: where the control plane reads the gateway's
	// /readyz for the model status of the admin UI (shadow.go). Optional.
	gatewayURL    string
	gatewayClient *http.Client // tests
}

// withKeyOrgs sets the UPSTREAM_KEY_ORGS allowlist.
func withKeyOrgs(k config.KeyOrgs) appOption {
	return func(s *appSettings) { s.keyOrgs = k }
}

type appOption func(*appSettings)

// withEnvUpstream tells the simulator the gateway's UPSTREAM_LLM_URL.
func withEnvUpstream(url string) appOption {
	return func(s *appSettings) { s.envUpstreamURL = url }
}

// newApp builds the Fiber app with all control plane routes.
func newApp(db *pgxpool.Pool, secret []byte, eng *policy.Engine, allowedOrigins string, opts ...appOption) *fiber.App {
	settings := &appSettings{}
	for _, o := range opts {
		o(settings)
	}
	if settings.ui == nil {
		settings.ui = web.Dist()
	}
	app := fiber.New(fiber.Config{
		ServerHeader: "guard-spec-cp",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})
	app.Use(clientIPMiddleware(settings.trustedProxies))
	app.Use(observe())
	if allowedOrigins != "" {
		app.Use(cors.New(cors.Config{AllowOrigins: allowedOrigins}))
	}
	app.Use(logger.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	mountUI(app, settings.ui)

	v1 := app.Group("/v1")
	id := newIdentity(db, secret, settings)
	perIP := func(max int) fiber.Handler {
		return limiter.New(limiter.Config{Max: max, Expiration: time.Minute, KeyGenerator: clientIP})
	}
	perUser := limiter.New(limiter.Config{Max: 10, Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return "user:" + auth.UserID(c).String() }})

	v1.Post("/auth/login", perIP(10), id.login)
	// The token is the credential here, so it gets the login's limit.
	v1.Post("/invites/accept", perIP(10), acceptInvite(db, id))
	// The second step of a login; also 5 attempts per mfa_token.
	v1.Post("/auth/mfa/verify", perIP(10), id.mfaVerify)
	v1.Get("/auth/providers", id.publicProviders)
	v1.Get("/auth/oidc/:id/start", perIP(30), id.oidcStart)
	v1.Get("/auth/oidc/:id/callback", perIP(30), id.oidcCallback)
	v1.Post("/auth/oidc/exchange", perIP(10), id.oidcExchange)
	v1.Get("/auth/saml/:id/metadata", perIP(60), id.samlMetadata)
	v1.Get("/auth/saml/:id/start", perIP(30), id.samlStart)
	v1.Post("/auth/saml/:id/acs", perIP(30), id.samlACS)

	// SCIM 2.0: the bearer token names the organization.
	scimBase := strings.TrimRight(settings.publicURL, "/") + "/v1/scim/v2"
	sc := &scimAPI{db: db, sessions: id.sessions, base: scimBase}
	scim := v1.Group("/scim/v2", perIP(600), sc.authenticate)
	scim.Get("/ServiceProviderConfig", sc.serviceProviderConfig)
	scim.Get("/ResourceTypes", sc.resourceTypes)
	scim.Get("/Schemas", sc.schemas)
	scim.Get("/Users", sc.listUsers)
	scim.Post("/Users", sc.createUser)
	scim.Get("/Users/:id", sc.getUser)
	scim.Put("/Users/:id", sc.replaceUser)
	scim.Patch("/Users/:id", sc.patchUser)
	scim.Delete("/Users/:id", sc.deleteUser)
	scim.Get("/Groups", sc.listGroups)
	scim.Post("/Groups", sc.createGroup)
	scim.Get("/Groups/:id", sc.getGroup)
	scim.Put("/Groups/:id", sc.replaceGroup)
	scim.Patch("/Groups/:id", sc.patchGroup)
	scim.Delete("/Groups/:id", sc.deleteGroup)
	v1.Get("/providers/catalog", providerCatalogHandler)
	v1.Get("/permissions", permissions)

	// 2FA setup takes a session token, or the mfa_token of an enrollment.
	enroll := v1.Group("/auth/mfa/totp", id.sessionOrEnroll(), perUser)
	enroll.Post("/setup", id.totpSetup)
	enroll.Post("/confirm", id.totpConfirm)

	// Alerts (alerts.go, docs/alerts.md). The Telegram webhook authenticates
	// with its own secret header, so it is mounted before the session check.
	settings.alertsRT = newAlertsRuntime(db, settings, id.lookup)
	v1.Post("/integrations/telegram/webhook", perIP(120), settings.alertsRT.telegramWebhook)
	v1.Get("/integrations/email/confirm", perIP(30), settings.alertsRT.confirmEmail)

	authed := v1.Group("", auth.Required(secret, id.lookup))

	authed.Get("/auth/me", id.me)
	authed.Post("/auth/logout", id.logout)
	authed.Get("/auth/sessions", id.listSessions)
	authed.Delete("/auth/sessions/:id", id.revokeSession)
	authed.Post("/auth/password", perUser, id.changePassword)
	authed.Post("/auth/mfa/recovery-codes/regenerate", perUser, id.regenerateRecoveryCodes)
	authed.Delete("/auth/mfa", perUser, id.disableMFA)
	authed.Post("/auth/identities/:providerId/link/start", perUser, id.linkStart)
	authed.Post("/auth/identities/link/complete", perUser, id.linkComplete)
	authed.Delete("/auth/identities/:providerId", id.unlinkIdentity)

	// Instance administration.
	instance := authed.Group("/admin", requireInstanceAdmin(db))
	instance.Get("/users", listAdminUsers(db))
	instance.Post("/users", createAdminUser(db))
	instance.Put("/users/:id", updateAdminUser(db, id.sessions))
	instance.Delete("/users/:id", deleteAdminUser(db, id.sessions))
	instance.Get("/identity-providers", id.listProviders)
	instance.Post("/identity-providers", id.createProvider)
	instance.Put("/identity-providers/:id", id.updateProvider)
	instance.Delete("/identity-providers/:id", id.deleteProvider)
	instance.Get("/activity", listInstanceActivity(db))

	// The gateway's running and available models (shadow.go); instance-wide.
	authed.Get("/gateway/models", getGatewayModels(settings))

	authed.Get("/organizations", listMyOrgs(db))
	authed.Post("/organizations", createOrg(db))
	authed.Post("/cel/validate", validateCEL(eng))
	// Rule editing helpers; they read no org data.
	authed.Get("/policy/schema", policySchema())
	authed.Post("/policy/parse", parseCondition(eng))
	authed.Post("/policy/format", formatCondition())

	viewer := auth.RequireRole(db, auth.RoleViewer)
	admin := auth.RequireRole(db, auth.RoleAdmin)
	owner := auth.RequireRole(db, auth.RoleOwner)

	authed.Get("/organizations/:orgId", viewer, getOrg(db))
	authed.Patch("/organizations/:orgId", admin, updateOrgSettings(db))
	authed.Delete("/organizations/:orgId", owner, deleteOrg(db))
	// Two-person approval (approvals.go, migration 027).
	authed.Get("/organizations/:orgId/approvals", admin, listApprovals(db))
	authed.Post("/organizations/:orgId/approvals/:id/approve", admin, approveRequest(db))
	authed.Post("/organizations/:orgId/approvals/:id/reject", admin, rejectRequest(db))
	authed.Get("/organizations/:orgId/guard-settings", viewer, getGuardSettings(db))
	authed.Put("/organizations/:orgId/guard-settings", admin, putGuardSettings(db))
	authed.Get("/organizations/:orgId/security", admin, getOrgSecurity(db))
	authed.Put("/organizations/:orgId/security", owner, putOrgSecurity(db))
	authed.Get("/organizations/:orgId/activity", admin, listOrgActivity(db))

	authed.Get("/organizations/:orgId/members", admin, listMembers(db))
	authed.Put("/organizations/:orgId/members/:userId", admin, updateMember(db))
	authed.Delete("/organizations/:orgId/members/:userId", admin, removeMember(db))
	authed.Post("/organizations/:orgId/members/:userId/reset-mfa", owner, resetMemberMFA(db, id.sessions))
	authed.Post("/organizations/:orgId/members/:userId/revoke-sessions", admin, revokeMemberSessions(db, id.sessions))

	authed.Get("/organizations/:orgId/api-keys", admin, listAPIKeys(db))
	authed.Post("/organizations/:orgId/api-keys", admin, createAPIKey(db))
	authed.Patch("/organizations/:orgId/api-keys/:keyId", admin, updateAPIKey(db))
	authed.Delete("/organizations/:orgId/api-keys/:keyId", admin, revokeAPIKey(db))
	authed.Get("/organizations/:orgId/scim/tokens", admin, listSCIMTokens(db, scimBase))
	authed.Post("/organizations/:orgId/scim/tokens", owner, createSCIMToken(db))
	authed.Delete("/organizations/:orgId/scim/tokens/:id", owner, revokeSCIMToken(db))
	authed.Get("/organizations/:orgId/group-roles", admin, getGroupRoles(db))
	authed.Put("/organizations/:orgId/group-roles", owner, putGroupRoles(db))

	authed.Get("/organizations/:orgId/projects", viewer, listProjects(db))
	authed.Post("/organizations/:orgId/projects", admin, createProject(db))
	authed.Get("/organizations/:orgId/projects/:projectId/members", viewer, listProjectMembers(db))
	authed.Put("/organizations/:orgId/projects/:projectId/members/:userId", admin, putProjectMember(db))
	authed.Delete("/organizations/:orgId/projects/:projectId/members/:userId", admin, deleteProjectMember(db))

	// Named upstreams and routing defaults (migration 011), with model
	// provider fields (migration 014).
	authed.Get("/organizations/:orgId/upstreams", viewer, listUpstreams(db))
	authed.Post("/organizations/:orgId/upstreams", admin, createUpstream(db, settings))
	authed.Put("/organizations/:orgId/upstreams/:id", admin, updateUpstream(db, settings))
	authed.Delete("/organizations/:orgId/upstreams/:id", admin, deleteUpstream(db))
	// Owner only: the test reaches out from the control plane with a key.
	authed.Post("/organizations/:orgId/upstreams/:id/test", owner, perUser, testUpstream(db, settings))
	authed.Put("/organizations/:orgId/default-upstream", admin, putOrgDefaultUpstream(db))
	authed.Put("/organizations/:orgId/projects/:projectId/default-upstream", admin, putProjectDefaultUpstream(db))

	// Config as code: the org's upstreams, defaults and policies as one YAML file.
	authed.Get("/organizations/:orgId/config", viewer, getConfig(db, eng))
	authed.Put("/organizations/:orgId/config", admin, putConfig(db, eng, settings))

	authed.Get("/organizations/:orgId/policies", viewer, listPolicies(db))
	// Before /policies/:id, which would take "simulate" as an id.
	authed.Post("/organizations/:orgId/policies/simulate", viewer, simulatePolicies(db, eng, settings))
	authed.Post("/organizations/:orgId/policies", admin, createPolicy(db, eng))
	authed.Put("/organizations/:orgId/policies/:id", admin, updatePolicy(db, eng))
	authed.Delete("/organizations/:orgId/policies/:id", admin, deletePolicy(db))
	// Policy history (policy_versions.go, migration 026).
	authed.Get("/organizations/:orgId/policies/:id/versions", viewer, listPolicyVersions(db))
	authed.Get("/organizations/:orgId/policies/:id/versions/diff", viewer, diffPolicyVersions(db))
	authed.Post("/organizations/:orgId/policies/:id/rollback", admin, rollbackPolicy(db, eng))

	authed.Get("/organizations/:orgId/requests", viewer, listRequests(db))
	// Stored content: the org's content_read_role, a reason when required,
	// and an activity log row for every read (content_access.go).
	authed.Post("/organizations/:orgId/requests/:requestId/content", viewer, readRequestContent(db, settings.contentKeys))
	// Aggregates of the request log over a window (dashboard.go).
	authed.Get("/organizations/:orgId/dashboard", viewer, getDashboard(db))
	// Shadow mode: the candidate model compared with the active one
	// (shadow.go, migration 017). The aggregates are for viewers; the list
	// of disagreeing requests for admins.
	authed.Get("/organizations/:orgId/shadow", viewer, getShadowSummary(db))
	authed.Get("/organizations/:orgId/shadow/disagreements", admin, listShadowDisagreements(db))

	// L3 exemplars of the org (migration 009); never stored in the repository.
	authed.Get("/organizations/:orgId/exemplars", viewer, listExemplars(db))
	authed.Post("/organizations/:orgId/exemplars", admin, createExemplar(db))
	authed.Put("/organizations/:orgId/exemplars/:id", admin, updateExemplar(db))
	authed.Delete("/organizations/:orgId/exemplars/:id", admin, deleteExemplar(db))

	// Real-time alerts and notifications (alerts.go, docs/alerts.md).
	registerAlertRoutes(v1, authed, db, settings.alertsRT, perIP)
	registerSIEMRoutes(authed, db, newSIEMResolver(settings.alertsCfg))

	// Invites, also under the short /orgs prefix.
	for _, prefix := range []string{"/organizations/:orgId", "/orgs/:orgId"} {
		authed.Get(prefix+"/invites", admin, listInvites(db))
		authed.Post(prefix+"/invites", admin, createInvite(db))
		authed.Delete(prefix+"/invites/:inviteId", admin, revokeInvite(db))
	}
	return app
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// serverError logs err and hides its details from the client.
func serverError(c *fiber.Ctx, err error) error {
	slog.Error("request failed", "path", c.Path(), "err", err)
	return c.Status(500).JSON(fiber.Map{"error": "internal error"})
}

// orgID returns the organization checked by auth.RequireRole.
func orgID(c *fiber.Ctx) uuid.UUID {
	id, _ := tenant.OrgID(c)
	return id
}

// bootstrapAdmin creates the first owner of the default organization.
func bootstrapAdmin(ctx context.Context, db *pgxpool.Pool, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return tenant.WithOrg(ctx, db, defaultOrgID, func(tx pgx.Tx) error {
		return bootstrapAdminTx(ctx, tx, email, hash)
	})
}

// bootstrapAdminTx runs the bootstrap in tx, scoped to the default org.
//
// It runs once per instance. An instance that already has an administrator
// is past it; one where it ran before (instance_state) is too, even if that
// admin was deleted since: restarting with the same ADMIN_EMAIL and
// ADMIN_PASSWORD must not bring the account back.
func bootstrapAdminTx(ctx context.Context, tx pgx.Tx, email, hash string) error {
	var hasAdmin bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE is_instance_admin AND disabled_at IS NULL)`).
		Scan(&hasAdmin); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO instance_state (key, value) VALUES ('bootstrap_admin', $1) ON CONFLICT (key) DO NOTHING`, email)
	if err != nil {
		return err
	}
	if hasAdmin || tag.RowsAffected() == 0 {
		return nil
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, hashed_password, is_instance_admin) VALUES ($1, $2, true)
		 ON CONFLICT (email) DO UPDATE SET is_instance_admin = true RETURNING id`, email, hash).Scan(&userID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING`,
		userID, defaultOrgID)
	return err
}

// checkMFAKey refuses to start when users have 2FA but MFA_ENC_KEY is not
// set: their codes could not be checked, and they could not log in.
func checkMFAKey(ctx context.Context, db *pgxpool.Pool, box *auth.SecretBox) error {
	if box != nil {
		return nil
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM user_mfa WHERE totp_secret_enc IS NOT NULL`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("MFA_ENC_KEY is not set but %d users have two-factor authentication; "+
			"set MFA_ENC_KEY to the key their secrets were encrypted with", n)
	}
	slog.Warn("MFA_ENC_KEY is not set: two-factor authentication cannot be turned on " +
		"(generate one with: openssl rand -base64 32)")
	return nil
}

func createOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" || req.Slug == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and slug are required"})
		}
		id := uuid.New()
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if _, err := tx.Exec(c.Context(),
				`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
				id, req.Name, req.Slug); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO org_memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')`,
				auth.UserID(c), id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		return c.Status(201).JSON(fiber.Map{"id": id, "name": req.Name, "slug": req.Slug})
	}
}

func getOrg(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var org struct {
			ID                uuid.UUID  `json:"id"`
			Name              string     `json:"name"`
			Slug              string     `json:"slug"`
			Tier              string     `json:"tier"`
			AuditStoreContent bool       `json:"audit_store_content"`
			DefaultUpstreamID *uuid.UUID `json:"default_upstream_id"`
			CreatedAt         time.Time  `json:"created_at"`
		}
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Context(),
				`SELECT id, name, slug, tier, audit_store_content, default_upstream_id, created_at
				 FROM organizations WHERE id = $1`, id).
				Scan(&org.ID, &org.Name, &org.Slug, &org.Tier, &org.AuditStoreContent, &org.DefaultUpstreamID, &org.CreatedAt)
		})
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		return c.JSON(org)
	}
}

// updateOrgSettings changes org-level settings. audit_store_content opts the org
// into storing prompt and response content in audit rows (off by default, D6).
func updateOrgSettings(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var req struct {
			AuditStoreContent *bool  `json:"audit_store_content"`
			Reason            string `json:"reason"` // for a two-person approval request
		}
		if err := c.BodyParser(&req); err != nil || req.AuditStoreContent == nil {
			return c.Status(400).JSON(fiber.Map{"error": "audit_store_content (boolean) is required"})
		}
		// Turning storage on waits for a second admin when the org asks for it.
		var deferred bool
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if *req.AuditStoreContent {
				on, _, err := twoPersonSettings(c.Context(), tx, id)
				if err != nil {
					return err
				}
				var current bool
				if err := tx.QueryRow(c.Context(), `SELECT audit_store_content FROM organizations WHERE id = $1`, id).Scan(&current); err != nil {
					return err
				}
				if on && !current {
					deferred = true
					return nil
				}
			}
			_, err := tx.Exec(c.Context(),
				`UPDATE organizations SET audit_store_content = $1, updated_at = NOW() WHERE id = $2`,
				*req.AuditStoreContent, id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if deferred {
			return requestApproval(c, db, id, approvalContentStorage, id.String(), map[string]any{"audit_store_content": true}, req.Reason)
		}
		slog.Info("org audit content storage changed", "org", id, "enabled", *req.AuditStoreContent,
			"by", auth.UserID(c))
		logActivity(c, db, &id, "org.settings_changed", "organization",
			map[string]any{"audit_store_content": *req.AuditStoreContent})
		return c.JSON(fiber.Map{"id": id, "audit_store_content": *req.AuditStoreContent})
	}
}

func listAPIKeys(db *pgxpool.Pool) fiber.Handler {
	ks := keyset{sort: "created_at", id: "key_prefix", desc: true, idType: "text"}
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		pg, err := parsePage(c, true)
		if err != nil {
			return badPage(c, err)
		}
		keys := []fiber.Map{}
		var total int64
		args := []any{id}
		filter := ""
		if q := c.Query("q"); q != "" {
			args = append(args, likePattern(q))
			filter += fmt.Sprintf(" AND (alias ILIKE $%[1]d OR key_prefix ILIKE $%[1]d)", len(args))
		}
		switch c.Query("revoked") {
		case "":
		case "true":
			filter += " AND revoked_at IS NOT NULL"
		case "false":
			filter += " AND revoked_at IS NULL"
		default:
			return c.Status(400).JSON(fiber.Map{"error": "revoked must be true or false"})
		}
		countArgs := args
		err = tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			cond, args, err := ks.where(pg, args)
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT key_prefix, alias, project_id, rpm_limit::bigint, tpm_limit, created_at, expires_at, revoked_at
				 FROM api_keys WHERE org_id = $1`+filter+cond+ks.orderLimit(pg), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var prefix string
				var alias *string
				var projectID *uuid.UUID
				var rpm, tpm *int64
				var createdAt time.Time
				var expiresAt, revokedAt *time.Time
				if err := rows.Scan(&prefix, &alias, &projectID, &rpm, &tpm, &createdAt, &expiresAt, &revokedAt); err != nil {
					return err
				}
				keys = append(keys, fiber.Map{
					"key_prefix": prefix,
					"alias":      alias,
					"project_id": projectID,
					"rpm_limit":  rpm, // null: the gateway's RATE_LIMIT_RPM; 0: unlimited
					"tpm_limit":  tpm,
					"created_at": createdAt,
					"expires_at": expiresAt,
					"revoked":    revokedAt != nil,
				})
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if pg.Enveloped {
				return tx.QueryRow(c.Context(), `SELECT count(*) FROM api_keys WHERE org_id = $1`+filter, countArgs...).Scan(&total)
			}
			return nil
		})
		if errors.Is(err, errBadCursor) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		if pg.Enveloped {
			items, next := page(keys, pg.Limit, func(m fiber.Map) pageCursor {
				return timeCursor(m["created_at"].(time.Time), m["key_prefix"].(string))
			})
			return pageJSON(c, items, next, total)
		}
		return c.JSON(fiber.Map{"data": keys})
	}
}

func createAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		var req struct {
			Alias     string     `json:"alias"`
			ProjectID *uuid.UUID `json:"project_id"`
			ExpiresAt *time.Time `json:"expires_at"`
			RPMLimit  optLimit   `json:"rpm_limit"`
			TPMLimit  optLimit   `json:"tpm_limit"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &req); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "invalid body: " + err.Error()})
			}
		}

		// Generate random key: gs_<32 hex chars>.
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "key gen failed"})
		}
		raw := "gs_" + hex.EncodeToString(buf)
		hash := tenant.HashKey(raw)
		prefix := raw[:11] // "gs_" + 8 chars

		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, id, req.ProjectID); err != nil {
				return err
			}
			_, err := tx.Exec(c.Context(),
				`INSERT INTO api_keys (key_hash, key_prefix, alias, org_id, project_id, expires_at, rpm_limit, tpm_limit, created_by)
				 VALUES ($1, $2, $3, $4, $5, $6, $7::int, $8, $9)`,
				hash, prefix, req.Alias, id, req.ProjectID, req.ExpiresAt, req.RPMLimit.Value, req.TPMLimit.Value, nullUUID(auth.UserID(c)))
			return err
		})
		if errors.Is(err, errUnknownProject) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &id, "api_key.created", prefix, map[string]any{"alias": req.Alias, "project_id": req.ProjectID})
		// Return plaintext key once only — cannot be recovered after this
		return c.Status(201).JSON(fiber.Map{
			"key":        raw,
			"key_prefix": prefix,
			"alias":      req.Alias,
			"project_id": req.ProjectID,
			"rpm_limit":  req.RPMLimit.Value,
			"tpm_limit":  req.TPMLimit.Value,
		})
	}
}

func revokeAPIKey(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		// keyId param is the key_prefix (we display prefix, never the hash)
		err := tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(c.Context(),
				`UPDATE api_keys SET revoked_at = NOW()
				 WHERE key_prefix = $1 AND org_id = $2 AND revoked_at IS NULL`,
				c.Params("keyId"), id)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &id, "api_key.revoked", c.Params("keyId"), nil)
		return c.Status(204).Send(nil)
	}
}

func listPolicies(db *pgxpool.Pool) fiber.Handler {
	ks := keyset{sort: "updated_at", id: "id", desc: true}
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		pg, err := parsePage(c, true)
		if err != nil {
			return badPage(c, err)
		}
		type pRow struct {
			ID          uuid.UUID       `json:"id"`
			ProjectID   *uuid.UUID      `json:"project_id"` // null: org-wide
			Name        string          `json:"name"`
			Description *string         `json:"description"`
			Version     int             `json:"version"`
			Enabled     bool            `json:"enabled"`
			LogOnly     bool            `json:"log_only"`
			Rules       json.RawMessage `json:"rules"`
			CreatedAt   time.Time       `json:"created_at"`
			UpdatedAt   time.Time       `json:"updated_at"`
		}
		policies := []pRow{}
		var total int64
		err = tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			cond, args, err := ks.where(pg, []any{id})
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				`SELECT id, project_id, name, description, version, enabled, log_only, rules, created_at, updated_at
				 FROM policies WHERE org_id = $1`+cond+ks.orderLimit(pg), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var p pRow
				if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Version, &p.Enabled, &p.LogOnly,
					&p.Rules, &p.CreatedAt, &p.UpdatedAt); err != nil {
					return err
				}
				policies = append(policies, p)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if pg.Enveloped {
				return tx.QueryRow(c.Context(), `SELECT count(*) FROM policies WHERE org_id = $1`, id).Scan(&total)
			}
			return nil
		})
		if errors.Is(err, errBadCursor) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		if pg.Enveloped {
			items, next := page(policies, pg.Limit, func(p pRow) pageCursor { return timeCursor(p.UpdatedAt, p.ID.String()) })
			return pageJSON(c, items, next, total)
		}
		return c.JSON(fiber.Map{"data": policies})
	}
}

func createPolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		var req struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Rules       json.RawMessage `json:"rules"`
			ProjectID   *uuid.UUID      `json:"project_id"` // null or absent: org-wide
			// Absent: enabled. A policy created disabled is never live, not
			// even between a create and a second PUT.
			Enabled *bool `json:"enabled"`
			// LogOnly: decisions are recorded, not applied (migration 026).
			LogOnly bool `json:"log_only"`
			// Reason is kept with the version (policy_versions.go).
			Reason string `json:"reason"`
		}
		if err := c.BodyParser(&req); err != nil || req.Name == "" {
			return c.Status(400).JSON(fiber.Map{"error": "name and rules are required"})
		}
		if len([]rune(req.Reason)) > maxReasonRunes {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("reason must be at most %d characters", maxReasonRunes)})
		}
		rules, targets, err := validateRules(eng, req.Rules)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		id := uuid.New()
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, req.ProjectID); err != nil {
				return err
			}
			if err := checkPolicyName(c.Context(), tx, org, req.Name, uuid.Nil); err != nil {
				return err
			}
			if err := checkRouteTargets(c.Context(), tx, org, targets); err != nil {
				return err
			}
			if _, err := tx.Exec(c.Context(),
				`INSERT INTO policies (id, org_id, project_id, name, description, rules, enabled, log_only)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				id, org, req.ProjectID, req.Name, req.Description, rules, req.Enabled == nil || *req.Enabled, req.LogOnly); err != nil {
				return err
			}
			return recordPolicyVersion(c.Context(), tx, org, id, auth.UserID(c), versionCreate, req.Reason, nil)
		})
		var unknownTarget *unknownTargetError
		if errors.Is(err, errUnknownProject) || errors.As(err, &unknownTarget) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, errDuplicatePolicyName) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		logActivity(c, db, &org, "policy.created", req.Name, map[string]any{"id": id, "log_only": req.LogOnly})
		return c.Status(201).JSON(fiber.Map{"id": id, "version": 1})
	}
}

func updatePolicy(db *pgxpool.Pool, eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		var req struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Enabled     *bool           `json:"enabled"`
			LogOnly     *bool           `json:"log_only"` // absent: unchanged
			Rules       json.RawMessage `json:"rules"`
			ProjectID   optUUID         `json:"project_id"` // absent: unchanged; null: org-wide
			Reason      string          `json:"reason"`     // kept with the version
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		if len([]rune(req.Reason)) > maxReasonRunes {
			return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("reason must be at most %d characters", maxReasonRunes)})
		}
		var targets []string
		if req.Rules != nil {
			if req.Rules, targets, err = validateRules(eng, req.Rules); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": err.Error()})
			}
		}
		var (
			updated int64
			version int
			// deferDisable: the org wants a second admin for disabling a
			// policy, and this save turns an enabled one off. Everything
			// else in the save applies now; the disable becomes a request.
			deferDisable bool
		)
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			if err := checkProject(c.Context(), tx, org, req.ProjectID.Value); err != nil {
				return err
			}
			if err := checkPolicyName(c.Context(), tx, org, req.Name, pID); err != nil {
				return err
			}
			if err := checkRouteTargets(c.Context(), tx, org, targets); err != nil {
				return err
			}
			if req.Enabled != nil && !*req.Enabled {
				on, _, err := twoPersonSettings(c.Context(), tx, org)
				if err != nil {
					return err
				}
				var enabled bool
				err = tx.QueryRow(c.Context(), `SELECT enabled FROM policies WHERE id = $1 AND org_id = $2`, pID, org).Scan(&enabled)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				if on && enabled {
					deferDisable = true
					req.Enabled = nil
				}
			}
			err := tx.QueryRow(c.Context(),
				`UPDATE policies SET
				 name = COALESCE(NULLIF($1,''), name),
				 description = COALESCE(NULLIF($2,''), description),
				 rules = COALESCE($3, rules),
				 enabled = COALESCE($4, enabled),
				 project_id = CASE WHEN $7 THEN $8::uuid ELSE project_id END,
				 log_only = COALESCE($9, log_only),
				 version = version + 1,
				 updated_at = NOW()
				 WHERE id = $5 AND org_id = $6 RETURNING version`,
				req.Name, req.Description, req.Rules, req.Enabled, pID, org,
				req.ProjectID.Set, req.ProjectID.Value, req.LogOnly).Scan(&version)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			updated = 1
			return recordPolicyVersion(c.Context(), tx, org, pID, auth.UserID(c), versionUpdate, req.Reason, nil)
		})
		var unknownTarget *unknownTargetError
		if errors.Is(err, errUnknownProject) || errors.As(err, &unknownTarget) {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, errDuplicatePolicyName) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		if err != nil {
			return serverError(c, err)
		}
		if updated == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "not found"})
		}
		logActivity(c, db, &org, "policy.updated", pID.String(), map[string]any{"enabled": req.Enabled, "log_only": req.LogOnly,
			"rules_changed": req.Rules != nil, "version": version, "reason": strings.TrimSpace(req.Reason)})
		if deferDisable {
			return requestApproval(c, db, org, approvalPolicyDisable, pID.String(), map[string]any{"enabled": false, "version": version}, req.Reason)
		}
		return c.JSON(fiber.Map{"id": pID, "updated": true, "version": version})
	}
}

func deletePolicy(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		org := orgID(c)
		pID, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid policy id"})
		}
		var deferred bool
		err = tenant.WithOrg(c.Context(), db, org, func(tx pgx.Tx) error {
			on, _, err := twoPersonSettings(c.Context(), tx, org)
			if err != nil {
				return err
			}
			if on {
				var exists bool
				if err := tx.QueryRow(c.Context(), `SELECT EXISTS (SELECT 1 FROM policies WHERE id = $1 AND org_id = $2)`, pID, org).
					Scan(&exists); err != nil {
					return err
				}
				deferred = exists
				return nil
			}
			_, err = tx.Exec(c.Context(),
				`DELETE FROM policies WHERE id = $1 AND org_id = $2`, pID, org)
			return err
		})
		if err != nil {
			return serverError(c, err)
		}
		if deferred {
			return requestApproval(c, db, org, approvalPolicyDelete, pID.String(), nil, c.Query("reason"))
		}
		logActivity(c, db, &org, "policy.deleted", pID.String(), nil)
		return c.Status(204).Send(nil)
	}
}

func validateCEL(eng *policy.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req struct {
			Condition json.RawMessage `json:"condition"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}
		celExpr, err := policy.JSONASTToCEL(req.Condition)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"valid": false, "error": err.Error()})
		}
		if err := eng.ValidateCEL(celExpr); err != nil {
			return c.Status(400).JSON(fiber.Map{"valid": false, "error": err.Error()})
		}
		return c.JSON(fiber.Map{"valid": true, "cel_expression": celExpr})
	}
}

var errDuplicatePolicyName = errors.New("a policy with this name already exists in this organization")

// checkPolicyName refuses a name another policy of org (other than self)
// already has: the config file names policies by name. The org row lock
// serializes concurrent saves, as a config apply does; older databases may
// still hold duplicates, so there is no unique index.
func checkPolicyName(ctx context.Context, tx pgx.Tx, org uuid.UUID, name string, self uuid.UUID) error {
	if name == "" {
		return nil // an update that keeps the name
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, org); err != nil {
		return err
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM policies WHERE org_id = $1 AND name = $2 AND id <> $3)`,
		org, name, self).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return errDuplicatePolicyName
	}
	return nil
}

// validateRules checks each rule and returns the list to store, with rule IDs
// filled in, and the route targets the rules name (checked against the org's
// upstreams by checkRouteTargets, inside the transaction that saves them).
func validateRules(eng *policy.Engine, raw json.RawMessage) (json.RawMessage, []string, error) {
	rules, err := eng.ValidateRules(raw)
	if err != nil {
		return nil, nil, err
	}
	stored, err := json.Marshal(rules)
	return stored, routeTargets(rules), err
}

func listRequests(db *pgxpool.Pool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := orgID(c)
		pg, err := parsePage(c, true)
		if err != nil {
			return badPage(c, err)
		}
		if !pg.Enveloped {
			pg.Limit = 100 // the unpaged answer of earlier releases: the newest 100
		}
		ks := keyset{sort: "created_at", id: "id", desc: true}

		type row struct {
			ID             uuid.UUID  `json:"id"`
			Model          *string    `json:"model"`
			Action         string     `json:"action"`
			RuleID         *uuid.UUID `json:"rule_id"`
			InjectionLabel *string    `json:"injection_label"`
			InjectionScore float32    `json:"injection_score"`
			ToxicityScore  float32    `json:"toxicity_score"`
			AnomalyScore   float32    `json:"anomaly_score"`
			HadTagChars    bool       `json:"had_tag_chars"`
			HadBidi        bool       `json:"had_bidi"`
			LatencyMs      *int       `json:"latency_ms"`
			RequestSHA256  *string    `json:"request_sha256"`
			RequestBytes   *int       `json:"request_bytes"`
			ResponseSHA256 *string    `json:"response_sha256"`
			ResponseBytes  *int       `json:"response_bytes"`
			// The named upstream the request went to (or failed to reach);
			// null for UPSTREAM_LLM_URL, the stub and refused requests.
			RouteTarget *string `json:"route_target"`
			// How many identical refused requests the row stands for when
			// retries were folded into it (migration 019); null for one.
			RepeatCount *int `json:"repeat_count"`
			// Tags is the pii_entities column: kinds and counts the gateway
			// noted, such as input:pii_email=1 or input:unscanned_image=2,
			// never values.
			Tags []string `json:"pii_entities"`
			// HasContent: the row stores the prompt or the answer. The
			// content itself is read one row at a time, with its own
			// permission and a logged reason (POST .../requests/{id}/content).
			HasContent bool      `json:"has_content"`
			CreatedAt  time.Time `json:"created_at"`
		}
		reqs := []row{}
		var total int64
		var capped bool
		err = tenant.WithOrg(c.Context(), db, id, func(tx pgx.Tx) error {
			args := []any{id}
			filter := ""
			if action := c.Query("action"); action != "" {
				args = append(args, action)
				filter += fmt.Sprintf(" AND action = $%d", len(args))
			}
			// Search over the row's metadata, never the stored prompt or
			// response content.
			if q := c.Query("q"); q != "" {
				args = append(args, likePattern(q))
				filter += fmt.Sprintf(` AND (id::text ILIKE $%[1]d OR model ILIKE $%[1]d OR route_target ILIKE $%[1]d
				  OR action ILIKE $%[1]d OR injection_label ILIKE $%[1]d)`, len(args))
			}
			if pg.Enveloped {
				var err error
				if total, capped, err = cappedCount(c.Context(), tx, `FROM requests WHERE org_id = $1`+filter, args); err != nil {
					return err
				}
			}
			cond, args, err := ks.where(pg, args)
			if err != nil {
				return err
			}
			rows, err := tx.Query(c.Context(),
				// The scores and flags are nullable columns (rows written by
				// older gateways or by hand); they read as 0 and false.
				`SELECT id, model, action, rule_id, injection_label,
				        COALESCE(injection_score, 0), COALESCE(toxicity_score, 0), COALESCE(anomaly_score, 0),
				        COALESCE(had_tag_chars, false), COALESCE(had_bidi, false), latency_ms,
				        request_sha256, request_bytes, response_sha256, response_bytes, route_target, repeat_count,
				        COALESCE(pii_entities, '{}'),
				        (request_content IS NOT NULL OR response_content IS NOT NULL), created_at
				 FROM requests WHERE org_id = $1`+filter+cond+ks.orderLimit(pageReq{Limit: pg.Limit, Enveloped: true}),
				args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.ID, &r.Model, &r.Action, &r.RuleID, &r.InjectionLabel, &r.InjectionScore, &r.ToxicityScore,
					&r.AnomalyScore, &r.HadTagChars, &r.HadBidi, &r.LatencyMs,
					&r.RequestSHA256, &r.RequestBytes, &r.ResponseSHA256, &r.ResponseBytes, &r.RouteTarget, &r.RepeatCount,
					&r.Tags, &r.HasContent, &r.CreatedAt); err != nil {
					return err
				}
				reqs = append(reqs, r)
			}
			return rows.Err()
		})
		if errors.Is(err, errBadCursor) {
			return badPage(c, err)
		}
		if err != nil {
			return serverError(c, err)
		}
		reqs, next := page(reqs, pg.Limit, func(r row) pageCursor { return timeCursor(r.CreatedAt, r.ID.String()) })
		if pg.Enveloped {
			// The count stops at cappedTotalLimit rows (total_capped).
			return c.JSON(fiber.Map{"items": reqs, "next_cursor": next, "total": total, "total_capped": capped})
		}
		return c.JSON(fiber.Map{"data": reqs, "total": len(reqs)})
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

type appConfig struct {
	ListenAddr     string
	DatabaseURL    string
	JWTSecret      string
	AdminEmail     string
	AdminPassword  string
	AllowedOrigins string
	// UpstreamURL is the gateway's UPSTREAM_LLM_URL, shown by the simulator
	// (without credentials). Optional.
	UpstreamURL string
	// GatewayURL (GATEWAY_URL) is the gateway's base URL inside the
	// deployment, such as http://gateway:8080, for the model status. Optional.
	GatewayURL string
	// MFAEncKey (MFA_ENC_KEY) encrypts TOTP secrets: 32 bytes in base64.
	MFAEncKey string
	// PublicBaseURL (PUBLIC_BASE_URL) is the external origin of the control
	// plane, for SSO callback urls.
	PublicBaseURL string
	// UpstreamAllowPrivate (UPSTREAM_ALLOW_PRIVATE) lets upstream connection
	// tests reach private addresses, as it does for the gateway.
	UpstreamAllowPrivate bool
	// TrustedProxies (TRUSTED_PROXIES) are reverse proxies whose
	// X-Forwarded-For is believed.
	TrustedProxies    []*net.IPNet
	trustedProxiesErr error
}

func loadConfig() appConfig {
	cfg := appConfig{
		ListenAddr:     getenv("LISTEN_ADDR", ":8081"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		JWTSecret:      secretsrc.Getenv("JWT_SECRET"),
		AdminEmail:     os.Getenv("ADMIN_EMAIL"),
		AdminPassword:  secretsrc.Getenv("ADMIN_PASSWORD"),
		AllowedOrigins: os.Getenv("ALLOWED_ORIGINS"),
		GatewayURL:     strings.TrimSpace(os.Getenv("GATEWAY_URL")),
		UpstreamURL:    redactURL(os.Getenv("UPSTREAM_LLM_URL")),
		MFAEncKey:      secretsrc.Getenv("MFA_ENC_KEY"),
		PublicBaseURL:  os.Getenv("PUBLIC_BASE_URL"),
		// Invalid values are refused by check.
		UpstreamAllowPrivate: strings.EqualFold(os.Getenv("UPSTREAM_ALLOW_PRIVATE"), "true"),
	}
	cfg.TrustedProxies, cfg.trustedProxiesErr = parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	return cfg
}

// redactURL drops credentials and the query from a URL that is shown to users.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// check refuses missing, default and weak secrets unless GUARD_ENV=dev.
func (cfg appConfig) check() error {
	if cfg.DatabaseURL == "" {
		return errors.New("DATABASE_URL is not set; set DATABASE_URL to the application role's connection string, " +
			"such as postgres://guardspec_app@host:5432/guardspec (password in the URL or PGPASSWORD)")
	}
	if cfg.JWTSecret == "" {
		// Even dev mode needs a key to sign with.
		return errors.New("JWT_SECRET is not set; set JWT_SECRET to a random value of at least 32 bytes " +
			"(for example: openssl rand -hex 32)")
	}
	if cfg.trustedProxiesErr != nil {
		return cfg.trustedProxiesErr
	}
	if v := os.Getenv("UPSTREAM_ALLOW_PRIVATE"); v != "" {
		if _, err := strconv.ParseBool(v); err != nil {
			return errors.New("UPSTREAM_ALLOW_PRIVATE must be true or false")
		}
	}
	if cfg.PublicBaseURL != "" {
		u, err := url.Parse(cfg.PublicBaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.User != nil {
			return errors.New("PUBLIC_BASE_URL must be an origin such as https://guard.example.com")
		}
	}
	// The dev key of docker-compose.override.yml decodes to "dev-only-...".
	for _, k := range strings.Split(cfg.MFAEncKey, ",") {
		k = strings.TrimSpace(k)
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil && k != "" &&
			config.IsKnownDefault(string(raw)) && !config.DevMode() {
			return errors.New("MFA_ENC_KEY is the development key; set MFA_ENC_KEY to 32 random bytes in base64 " +
				"(openssl rand -base64 32)")
		}
	}
	var c config.Checker
	c.Secret("JWT_SECRET", cfg.JWTSecret)
	if cfg.AdminEmail != "" {
		c.Password("ADMIN_PASSWORD", cfg.AdminPassword)
	}
	c.DatabaseURL("DATABASE_URL", cfg.DatabaseURL)
	return c.Err()
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

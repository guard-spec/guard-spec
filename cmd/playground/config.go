// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// config is the proxy's configuration, read from the environment
// (deploy/playground/README.md lists every variable).
type config struct {
	Addr           string
	GatewayURL     string
	GatewayKey     string
	GatewayTimeout time.Duration
	// AllowedOrigins are the exact origins (scheme://host[:port]) a browser
	// may call from. Others get 403.
	AllowedOrigins map[string]bool
	// AllowNoOrigin accepts requests without an Origin header (curl, scripts).
	AllowNoOrigin bool
	// ClientIPHeader names the header that carries the client address, set by
	// a reverse proxy in front (CF-Connecting-IP, Fly-Client-IP,
	// X-Forwarded-For: its last entry). Empty: the TCP peer address.
	ClientIPHeader string

	PerMinute    int // per client IP
	PerDay       int // per client IP
	GlobalPerMin int // all clients together; over it: 503
	MaxTracked   int // client IPs kept in the limiter; over it: 503
	MaxInput     int // bytes of text
	MaxBody      int // bytes of the request body
	MaxInFlight  int // concurrent gateway calls; over it: 503

	TurnstileSecret    string // empty: off
	TurnstileVerifyURL string
	StatsInterval      time.Duration
}

func loadConfig(env func(string) string) (config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(env(k)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	num := func(k string, def, lo, hi int) int {
		n, err := strconv.Atoi(get(k, strconv.Itoa(def)))
		if err != nil || n < lo || n > hi {
			errs = append(errs, fmt.Errorf("%s must be a number from %d to %d", k, lo, hi))
		}
		return n
	}
	dur := func(k string, def time.Duration) time.Duration {
		d, err := time.ParseDuration(get(k, def.String()))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration such as 5s", k))
		}
		return d
	}
	boolean := func(k string) bool {
		b, err := strconv.ParseBool(get(k, "false"))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s must be true or false", k))
		}
		return b
	}

	c := config{
		Addr:               get("PLAYGROUND_ADDR", ":8090"),
		GatewayURL:         strings.TrimRight(get("GATEWAY_URL", ""), "/"),
		GatewayKey:         get("GATEWAY_API_KEY", ""),
		GatewayTimeout:     dur("GATEWAY_TIMEOUT", 5*time.Second),
		AllowedOrigins:     map[string]bool{},
		AllowNoOrigin:      boolean("ALLOW_NO_ORIGIN"),
		ClientIPHeader:     get("CLIENT_IP_HEADER", ""),
		PerMinute:          num("RATE_PER_MINUTE", 10, 1, 10_000),
		PerDay:             num("RATE_PER_DAY", 200, 1, 1_000_000),
		GlobalPerMin:       num("GLOBAL_RATE_PER_MINUTE", 300, 1, 1_000_000),
		MaxTracked:         num("MAX_TRACKED_CLIENTS", 100_000, 100, 10_000_000),
		MaxInput:           num("MAX_INPUT_BYTES", 4096, 1, 65_536),
		MaxInFlight:        num("MAX_IN_FLIGHT", 8, 1, 1024),
		TurnstileSecret:    get("TURNSTILE_SECRET", ""),
		TurnstileVerifyURL: get("TURNSTILE_VERIFY_URL", "https://challenges.cloudflare.com/turnstile/v0/siteverify"),
		StatsInterval:      dur("STATS_INTERVAL", 5*time.Minute),
	}
	// JSON escaping can grow text up to 6x (\uXXXX); the default leaves room
	// for escaped non-ASCII text, such as Vietnamese, plus the other fields.
	c.MaxBody = num("MAX_BODY_BYTES", 6*c.MaxInput+1024, c.MaxInput, 1<<20)

	for _, o := range strings.Split(get("ALLOWED_ORIGINS", "https://guardspec.io"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" {
			errs = append(errs, fmt.Errorf("ALLOWED_ORIGINS: %q is not an origin such as https://guardspec.io", o))
			continue
		}
		c.AllowedOrigins[o] = true
	}
	if c.GatewayURL == "" {
		errs = append(errs, errors.New("GATEWAY_URL is required, such as http://gateway:8080"))
	} else if u, err := url.Parse(c.GatewayURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, errors.New("GATEWAY_URL must be an http(s) URL"))
	}
	if c.GatewayKey == "" {
		errs = append(errs, errors.New("GATEWAY_API_KEY is required: the gateway key of the playground org"))
	}
	return c, errors.Join(errs...)
}

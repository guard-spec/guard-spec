// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// runHealth is the "health" subcommand used by the image HEALTHCHECK and the
// compose and Kubernetes checks: the image has no shell or curl. It asks the
// gateway listening on LISTEN_ADDR (default :8080) for path (default
// /readyz) and returns 0 on HTTP 200, 1 otherwise.
//
//	gateway health            # /readyz
//	gateway health /health    # liveness only
func runHealth(args []string, getenv func(string) string, errOut io.Writer) int {
	path := "/readyz"
	if len(args) > 0 && args[0] != "" {
		path = args[0]
	}
	if !strings.HasPrefix(path, "/") {
		_, _ = fmt.Fprintln(errOut, "health: the path must start with /")
		return 2
	}
	u := "http://" + healthHost(getenv("LISTEN_ADDR")) + path
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "health:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(errOut, "health: %s answered %d\n", path, resp.StatusCode)
		return 1
	}
	return 0
}

// healthHost turns a listen address into the address to call: an empty or
// wildcard host becomes the loopback address.
func healthHost(listen string) string {
	if listen == "" {
		listen = ":8080"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:8080"
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

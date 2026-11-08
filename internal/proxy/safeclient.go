// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ValidateTargetURL checks a URL the control plane sends to on an
// organization's behalf (alert webhooks, A2A agents), with the rules of
// upstream base URLs: no credentials, no cloud metadata names, no
// link-local, multicast or unspecified address literals. Only https is
// accepted unless allowHTTP is set. A query is allowed: webhook URLs carry
// their tokens there. The dialer of SafeClient applies the address rules
// again after DNS.
func ValidateTargetURL(raw string, allowHTTP bool) error {
	if len(raw) > maxBaseURL {
		return fmt.Errorf("url is longer than %d bytes", maxBaseURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("url is not valid")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	default:
		return errors.New("url must be an absolute https url")
	}
	if u.Host == "" {
		return errors.New("url must be an absolute https url")
	}
	if u.User != nil {
		return errors.New("url must not contain credentials")
	}
	if u.Fragment != "" {
		return errors.New("url must not have a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if deniedHosts[host] {
		return fmt.Errorf("url host %s is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil && deniedIP(ip) {
		return fmt.Errorf("url address %s is not allowed", host)
	}
	return nil
}

// SafeClient returns an HTTP client for outgoing notifications: it never
// follows redirects, gives up after timeout, and its dialer refuses
// link-local, metadata, multicast and unspecified addresses after DNS, and
// loopback, private and CGNAT ones too when denyPrivate is set.
func SafeClient(denyPrivate bool, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil, // a proxy would dial for us and skip the address check
			DialContext:           (&net.Dialer{Timeout: timeout, Control: dialControl(denyPrivate)}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// SafeDialer is the dialer of SafeClient, for protocols other than HTTP
// (syslog over TLS to a SIEM): it refuses the same addresses after DNS.
func SafeDialer(denyPrivate bool, timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: dialControl(denyPrivate)}
}

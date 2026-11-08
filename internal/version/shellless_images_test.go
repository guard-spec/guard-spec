// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// lastShellImage is the last release whose gateway image had a shell and curl.
// The images built from build/gateway.Dockerfile after it have neither, and
// the deployment files that run the released image (they pin its version)
// must use the binaries' subcommands instead. While the pinned version is
// still lastShellImage they must keep the shell forms, or the files on main
// break for everyone running the released image.
const lastShellImage = "0.3.1"

// shellForms lists, per deployment file, what only the shell images support
// and what replaces it.
var shellForms = []struct {
	file, forbidden, use string
}{
	{"docker-compose.yml", `test: ["CMD", "curl"`, `test: ["CMD", "/app/gateway", "health", "/health"]`},
	{"docker-compose.yml", "./models pull -manifest manifest.yaml -dir /models/cache \"$$@\"", `entrypoint: ["./models", "init", "-manifest", "manifest.yaml", "-dir", "/models/cache"]`},
	{"deploy/compose/production/docker-compose.yml", `test: ["CMD", "curl"`, `test: ["CMD", "/app/gateway", "health"]`},
	{"deploy/compose/production/docker-compose.yml", "./models pull -manifest manifest.yaml -dir /models/cache \"$$@\"", `entrypoint: ["./models", "init", "-manifest", "manifest.yaml", "-dir", "/models/cache"]`},
	{"deploy/helm/guard-spec/templates/gateway.yaml", "/bin/sh", "the models init branch (drop gateway.image.shell from values.yaml and tests/kind/values.yaml)"},
	{"deploy/helm/guard-spec/templates/migrations.yaml", "/bin/sh", "the doctor copy-migrations branch (drop gateway.image.shell)"},
	{"deploy/terraform/aws/ecs.tf", `"CMD-SHELL", "curl`, `command = ["CMD", "/app/gateway", "health"]`},
	{"docs/deploy/aws.md", `"CMD-SHELL", "curl`, `"command": ["CMD", "/app/gateway", "health"]`},
}

func TestDeployFilesMatchImageShell(t *testing.T) {
	root := filepath.Join("..", "..")
	chart, err := os.ReadFile(filepath.Join(root, "deploy/helm/guard-spec/Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^appVersion:\s*"?([^"\s]+)"?`).FindSubmatch(chart)
	if m == nil {
		t.Fatal("Chart.yaml: no appVersion")
	}
	shellImage := string(m[1]) == lastShellImage
	for _, f := range shellForms {
		b, err := os.ReadFile(filepath.Join(root, f.file))
		if err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(string(b), f.forbidden)
		switch {
		case !shellImage && has:
			t.Errorf("%s: the %s image has no shell or curl; replace %q with %s",
				f.file, m[1], f.forbidden, f.use)
		case shellImage && !has:
			t.Errorf("%s: the released %s image still needs %q (the shell-less image ships with the next release); "+
				"switch it in the release that bumps the version, or update shellForms", f.file, lastShellImage, f.forbidden)
		}
	}
}

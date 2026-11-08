// govulncheck for CI (ci.yml, .github/workflows/vuln-scan.yml), pinned here
// and kept out of the main module so its dependencies never reach the
// binaries; Dependabot updates it like any other module. Run it with
//
//	go tool -modfile=tools/go.mod govulncheck ./...
module github.com/guard-spec/guard-spec/tools

go 1.26.10

tool golang.org/x/vuln/cmd/govulncheck

require (
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
)

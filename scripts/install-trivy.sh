#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Installs the pinned Trivy release for CI (.github/workflows/vuln-scan.yml)
# into DIR (default: $RUNNER_TEMP/bin or ./bin), checking the SHA-256 of the
# archive. The pin was checked against Trivy's signed checksums with
#   cosign verify-blob --bundle trivy_<v>_checksums.txt.sigstore.json \
#     --certificate-identity https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v<v> \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com trivy_<v>_checksums.txt
# Update VERSION and SHA256 together (linux amd64), after the same check, and
# prefer a release that is at least two weeks old.
set -eu

VERSION=0.76.1
SHA256=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0

dir=${1:-${RUNNER_TEMP:-.}/bin}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
archive="trivy_${VERSION}_Linux-64bit.tar.gz"
curl -fsSLo "$tmp/$archive" "https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/${archive}"
echo "$SHA256  $tmp/$archive" | sha256sum -c -
mkdir -p "$dir"
tar -xzf "$tmp/$archive" -C "$tmp" trivy
install -m 0755 "$tmp/trivy" "$dir/trivy"
"$dir/trivy" --version

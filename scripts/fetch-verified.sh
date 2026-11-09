#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Downloads URL to OUT and checks its SHA-256; on a mismatch OUT is removed
# and the script fails. Used by CI for pinned tool downloads.
#
#   scripts/fetch-verified.sh <url> <sha256> <out>
#
# DOWNLOAD_CACHE=<dir> (CI: a directory restored by actions/cache): a file
# there named <sha256>-<basename of url> is copied to OUT instead of
# downloading, and kept only when the copy has the pinned SHA-256; otherwise
# the URL is downloaded as usual and the verified file is put in the cache
# for the next run. A cache entry can save a download, never skip the check.
set -eu

usage='usage: fetch-verified.sh <url> <sha256> <out>'
url=${1:?$usage}
want=${2:?$usage}
out=${3:?$usage}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

cached=
if [ -n "${DOWNLOAD_CACHE:-}" ]; then
  cached=$DOWNLOAD_CACHE/$want-${url##*/}
  if [ -f "$cached" ]; then
    cp "$cached" "$out"
    if [ "$(sha256 "$out")" = "$want" ]; then
      echo "fetch-verified: ${url##*/} from the cache, sha256 ok"
      exit 0
    fi
    echo "fetch-verified: ignoring $cached: sha256 mismatch" >&2
    rm -f "$out" "$cached"
  fi
fi

# GitHub Releases answered 504 for hours on 2026-11-09: retry for up to 5
# minutes, on any error, before failing (the cache covers longer outages).
curl -fsSL --retry 8 --retry-delay 5 --retry-all-errors --retry-max-time 300 -o "$out" "$url"
got=$(sha256 "$out")
if [ "$got" != "$want" ]; then
  echo "fetch-verified: sha256 mismatch for $url: got $got, want $want" >&2
  rm -f "$out"
  exit 1
fi
echo "fetch-verified: ${url##*/} downloaded, sha256 ok"
if [ -n "$cached" ]; then
  mkdir -p "$DOWNLOAD_CACHE"
  cp "$out" "$cached"
fi

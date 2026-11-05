#!/bin/sh
# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Renders the README diagrams (context, component, flow; English and Vietnamese) to
# docs/images/*.png with headless Chrome. The pages load the Inter font and
# the Lucide icons (ISC) from the network.
#
# Usage: docs/diagrams/render.sh   (CHROME=/path/to/chrome to override)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$here/../images" && pwd)
chrome=${CHROME:-}
if [ -z "$chrome" ]; then
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium chromium-browser; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then chrome=$c; break; fi
  done
fi
[ -n "$chrome" ] || { echo "render.sh: Chrome not found; set CHROME" >&2; exit 1; }

render() { # page size
  "$chrome" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files \
    --force-device-scale-factor=2 --window-size="$2" --virtual-time-budget=10000 \
    --screenshot="$out/diagram-$1.png" "file://$here/$1.html" >/dev/null 2>&1
  echo "docs/images/diagram-$1.png"
}
render context 1600,990
render context.vi 1600,990
render component 1800,1080
render component.vi 1800,1080
render flow 1500,1700
render flow.vi 1500,1700

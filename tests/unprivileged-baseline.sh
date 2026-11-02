#!/usr/bin/env bash
# unprivileged-baseline.sh — evidence for the claim that an unprivileged sweep is blind.
# Runs the honest dispatch as uid 65534, with no extra mounts, and records what it cannot
# read. This exists because the claim "unprivileged, the baseline itself was blind on
# /root" was first observed in a terminal transcript that was then overwritten; a claim
# without a kept receipt is exactly what this week's rule says not to publish.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
node build-manifest.mjs --label unprivileged >/dev/null
MANIFEST="$HERE/manifest.json"
eval "$(node "$HERE/runner/manifest-read.mjs" "$MANIFEST")"
mkdir -p receipts
docker run --rm --network none --read-only --tmpfs /tmp:size=8m \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  -v "$PERMIT_HOST:/cell/permit:ro" -v "$CODE_HOST:/cell/code:ro" \
  -v "$HERE/runner:/cell/lib:ro" -v "$MANIFEST:/cell/manifest.json:ro" \
  node:24-alpine node /cell/code/probe.mjs >receipts/unprivileged.stdout 2>/dev/null
rc=$?
node -e '
const fs = require("fs");
const r = JSON.parse(fs.readFileSync("receipts/unprivileged.stdout", "utf8"));
fs.writeFileSync("receipts/unprivileged.json", JSON.stringify({
  label: "unprivileged",
  cell_exit: Number(process.argv[1]),
  uid_inside_cell: 65534,
  extra_mounts: [],
  unreadable_dirs: r.unreadable_dirs,
  files_swept: r.files_swept,
  permit_matches_commit: r.permit_matches_commit,
}, null, 2) + "\n");
' "$rc"
rm -f receipts/unprivileged.stdout
cat receipts/unprivileged.json

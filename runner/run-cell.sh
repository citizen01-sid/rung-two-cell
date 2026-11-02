#!/usr/bin/env bash
# run-cell.sh — dispatch the sealed cell. The runner is the outside party: it reads
# the committed manifest, refuses if the input moved, and only then starts the cell.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${1:-$HERE/manifest.json}"
OUT="${2:-$HERE/receipts/receipt.json}"
EXTRA_MOUNT="${RUNG2_EXTRA_MOUNT:-}"      # used by negative control 2 only
FORCE="${RUNG2_FORCE_DISPATCH:-0}"        # negative control 1b: bypass the pre-check

fail() { echo "DISPATCH-REFUSED: $*" >&2; exit 1; }
[ -f "$MANIFEST" ] || fail "no manifest at $MANIFEST (run build-manifest.mjs first)"
MANIFEST="$(cd "$(dirname "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"

# single implementation of the tree hash, shared with the cell
eval "$(node "$HERE/runner/manifest-read.mjs" "$MANIFEST")"

# --- pre-dispatch: the committed tree must still be the tree on disk -----------
if [ "$FORCE" != "1" ] && [ "$ACTUAL_TREE" != "$PERMIT_TREE" ]; then
  fail "permit tree changed since commitment ($ACTUAL_TREE != $PERMIT_TREE)"
fi

mkdir -p "$(dirname "$OUT")"
MOUNTS=(-v "$PERMIT_HOST:/cell/permit:ro" -v "$CODE_HOST:/cell/code:ro" -v "$HERE/runner:/cell/lib:ro" -v "$MANIFEST:/cell/manifest.json:ro")
if [ -n "$EXTRA_MOUNT" ]; then
  # Accept either "<path>" (mounted at the same path) or "<src>:<dst>" — the second
  # form is what a careless mount list looks like when it overlaps a probed deny path.
  if [ "${EXTRA_MOUNT#*:}" != "$EXTRA_MOUNT" ]; then
    MOUNTS+=(-v "$EXTRA_MOUNT:ro")
  else
    MOUNTS+=(-v "$EXTRA_MOUNT:$EXTRA_MOUNT:ro")
  fi
fi

# The sweep runs as root INSIDE the cell on purpose. A sweep that cannot read a
# directory cannot report it empty, and the boundary here is enforced by ABSENT
# MOUNTS, not by the uid: if root-in-cell cannot see the deny path, nothing in the
# cell can. Running unprivileged would trade a real claim for a blind spot — which is
# exactly the class of defect this instrument exists to catch (measured 15:2xZ: as
# uid 65534 the baseline came back UNKNOWN, blind on /root).
set +e
docker run --rm --network "$NETWORK" --read-only --tmpfs /tmp:size=8m \
  --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
  "${MOUNTS[@]}" "$IMAGE" node /cell/code/probe.mjs \
  >"$OUT.stdout" 2>"$OUT.stderr"
RC=$?
set -e

FORCE="$FORCE" RC="$RC" LABEL="$LABEL" NETWORK="$NETWORK" \
PERMIT_TREE="$PERMIT_TREE" ACTUAL_TREE="$ACTUAL_TREE" OUT="$OUT" \
node -e '
const fs = require("fs");
const e = process.env;
let receipt = null;
try { receipt = JSON.parse(fs.readFileSync(e.OUT + ".stdout", "utf8")); } catch { receipt = null; }
const payload = {
  label: e.LABEL,
  dispatched_at: new Date().toISOString(),
  cell_exit: Number(e.RC),
  precheck_bypassed: e.FORCE === "1",
  network: e.NETWORK,
  permit_tree_committed: e.PERMIT_TREE,
  permit_tree_pre_dispatch: e.ACTUAL_TREE,
  precheck_agreed: e.PERMIT_TREE === e.ACTUAL_TREE,
  receipt,
};
fs.writeFileSync(e.OUT, JSON.stringify(payload, null, 2) + "\n");
'
rm -f "$OUT.stdout" "$OUT.stderr"
[ "$RC" -eq 0 ] || { echo "CELL-EXIT $RC (see $OUT)"; exit "$RC"; }
echo "receipt: $OUT"

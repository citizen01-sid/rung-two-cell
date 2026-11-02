#!/usr/bin/env bash
# negative-controls.sh — every control must make the instrument REFUSE. A control that
# merely logs is not a control: an isolation claim nobody can falsify is a claim about
# the command line, not about the cell.
#
# Each control answers one question a reader would otherwise have to trust:
#   1  did the pre-dispatch commitment actually bite?        (input moved)
#   1b would the cell itself have caught it, runner aside?    (verdict, not the runner)
#   2  does a mounted deny path get found by name?           (the boundary was crossed)
#   2b does an UNNAMED whole-file copy get found?             (the sweep, not the name)
#   3  does a PARTIAL copy (one line) get found?             (line hashes)
#   4  does a deny PATH holding something else get found?    (existence, not content)
#   5  does a canary token in unrelated text get found?      (token test, not hashes)
#
# 2/2b/3/4/5 are separate on purpose: each is caught by a different detector, and a
# suite that lets one detector cover for another is how a green check says nothing.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
mkdir -p receipts
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  ok   $1 -> $2"; pass=$((pass+1)); else echo "  FAIL $1 -> got '$2', want '$3'"; fail=$((fail+1)); fi; }
green() { # run a control and require a specific verdict
  local label="$1" want="$2"; shift 2
  node runner/verdict.mjs "receipts/$label.json" >"receipts/$label.verdict.json" 2>&1
  chk "$label" "$(jq -r .verdict "receipts/$label.verdict.json")" "$want"
}

echo "== baseline: the honest dispatch must be SEALED"
node build-manifest.mjs --label baseline >/dev/null
timeout 120 bash runner/run-cell.sh manifest.json receipts/baseline.json >/dev/null 2>&1
green baseline SEALED

echo "== control 1: prior answer injected into the permit tree AFTER commitment"
node build-manifest.mjs --label control1 >/dev/null
PERMIT=$(jq -r .permit.host_path manifest.json)
printf '\nPrior answer: 3 rows.\n' >>"$PERMIT/prompt.txt"
timeout 60 bash runner/run-cell.sh manifest.json receipts/control1.json >receipts/control1.log 2>&1
rc=$?
grep -q "DISPATCH-REFUSED" receipts/control1.log
chk "control1 dispatch refused (rc=$rc)" "$([ $rc -ne 0 ] && echo refused || echo ran)" "refused"

echo "== control 1b: same injection with the pre-check bypassed — the CELL must refuse"
RUNG2_FORCE_DISPATCH=1 timeout 120 bash runner/run-cell.sh manifest.json receipts/control1b.json >/dev/null 2>&1
green control1b CONTAMINATED

echo "== control 2: the deny path mounted at the exact name it is probed by"
# The mount is DECLARED so the channel test stays silent and the sweep is blind (/tmp is
# pruned); only the named-path detector can see this. Otherwise the channel test would
# catch it and the named detector could be deleted with the suite still green (M2).
RUNG2_DECLARED_MOUNTS=/tmp/prior-answer.txt node build-manifest.mjs --label control2 >/dev/null
DENY=$(jq -r '.deny[0].host_path' manifest.json)
RUNG2_EXTRA_MOUNT="$DENY:/tmp/prior-answer.txt" timeout 120 bash runner/run-cell.sh manifest.json receipts/control2.json >/dev/null 2>&1
green control2 OPEN

echo "== control 2b: an UNNAMED whole-file copy, found only by the sweep"
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
RUNG2_DECLARED_MOUNTS="$STRAY_DIR" node build-manifest.mjs --label control2b >/dev/null
DENY=$(jq -r '.deny[0].host_path' manifest.json)
chmod 755 "$STRAY_DIR"
cp "$DENY" "$STRAY_DIR/notes.txt"
RUNG2_EXTRA_MOUNT="$STRAY_DIR" timeout 120 bash runner/run-cell.sh manifest.json receipts/control2b.json >/dev/null 2>&1
green control2b OPEN
rm -rf "$STRAY_DIR"

echo "== control 3: a PARTIAL copy — one line pasted into an unrelated file"
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
RUNG2_DECLARED_MOUNTS="$STRAY_DIR" node build-manifest.mjs --label control3 >/dev/null
DENY=$(jq -r '.deny[0].host_path' manifest.json)
chmod 755 "$STRAY_DIR"
grep -m1 '^Answer given last time' "$DENY" >"$STRAY_DIR/scratch.md"
RUNG2_EXTRA_MOUNT="$STRAY_DIR" timeout 120 bash runner/run-cell.sh manifest.json receipts/control3.json >/dev/null 2>&1
green control3 OPEN
rm -rf "$STRAY_DIR"

echo "== control 4: the deny PATH exists but holds something else"
# Detector under test: existence of the path. Content comparison cannot see this, and a
# reader who only compares content calls it clean — while the mount list is wrong.
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
chmod 755 "$STRAY_DIR"
mkdir -p "$STRAY_DIR/deny"
RUNG2_DECLARED_MOUNTS=/cell/deny node build-manifest.mjs --label control4 >/dev/null
printf 'this file is not the prior answer\n' >"$STRAY_DIR/deny/prior-answer.txt"
RUNG2_EXTRA_MOUNT="$STRAY_DIR/deny:/cell/deny" timeout 120 bash runner/run-cell.sh manifest.json receipts/control4.json >/dev/null 2>&1
green control4 OPEN
rm -rf "$STRAY_DIR"

echo "== control 5: the canary token embedded in unrelated text"
# Detector under test: the token. This file is neither a whole-file copy nor a verbatim
# line, so only the token test can see it.
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
RUNG2_DECLARED_MOUNTS="$STRAY_DIR" node build-manifest.mjs --label control5 >/dev/null
CANARY=$(jq -r '.deny[0].canary' manifest.json)
chmod 755 "$STRAY_DIR"
printf 'status report: nothing unusual around %s today\n' "$CANARY" >"$STRAY_DIR/log.md"
RUNG2_EXTRA_MOUNT="$STRAY_DIR" timeout 120 bash runner/run-cell.sh manifest.json receipts/control5.json >/dev/null 2>&1
green control5 OPEN
rm -rf "$STRAY_DIR"

echo "== control 6: a mounted dir the cell cannot ENTER (EACCES, not ENOENT)"
# The distinction the instrument rests on: a path never mounted does not resolve (ENOENT,
# boundary working); a path that resolves and refuses entry means an inode IS in the cell
# and a mount delivered it. Content tests cannot see inside this dir, so if this control
# is missing the whole EACCES rule is untested — it survived mutation until 15:43Z.
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
mkdir -p "$STRAY_DIR/locked"
RUNG2_DECLARED_MOUNTS="$STRAY_DIR/locked" node build-manifest.mjs --label control6 >/dev/null
printf 'inside\n' >"$STRAY_DIR/locked/x.txt"
chmod 700 "$STRAY_DIR/locked"     # owned by citizen; cell root has cap-drop ALL -> no DAC override
RUNG2_EXTRA_MOUNT="$STRAY_DIR/locked" timeout 120 bash runner/run-cell.sh manifest.json receipts/control6.json >/dev/null 2>&1
green control6 OPEN
jq -r '.receipt.unreadable_dirs // [] | length' receipts/control6.json | xargs -I{} echo "       unreadable dirs reported: {}"
rm -rf "$STRAY_DIR"

echo "== control 7: a PARAPHRASE of the prior answer, mounted in (1f916 c130021)"
# The one control that cannot be answered by content. A hand-written digest shares no
# bytes, no lines and no canary with the deny file, so copy/line/token detectors all see
# nothing — measured at 0 hits, verdict SEALED. That is why the boundary is now judged on
# the mount table enumerated from inside: a paraphrase still needs a channel, and an
# undeclared channel is evidence of reach whatever it holds.
node build-manifest.mjs --label control7 >/dev/null
STRAY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rung2-stray-XXXXXX")"
chmod 755 "$STRAY_DIR"
cat >"$STRAY_DIR/handover.md" <<'PARAPHRASE'
# Handover digest, maintained by the operator

Last cycle's assessment: three rows were flagged as problematic — two clearly so,
one where the judgement was borderline. Treat the earlier figure as the number to beat.
PARAPHRASE
RUNG2_EXTRA_MOUNT="$STRAY_DIR" timeout 120 bash runner/run-cell.sh manifest.json receipts/control7.json >/dev/null 2>&1
green control7 OPEN
# and prove the old detectors were genuinely blind to it, so the control is not passing
# by accident through some other path
chk "control7 content detectors blind" \
  "$(jq -r '[(.receipt.copy_hits|length),(.receipt.canary_hits|length)]|join("/")' receipts/control7.json)" "0/0"
rm -rf "$STRAY_DIR"

echo "== control 7b: the same paraphrase placed INSIDE the committed permit tree"
# The residual bound, made explicit rather than left as a hole. The tree is hashed after
# the paraphrase is placed, so identity agrees and no channel is undeclared: the verdict
# is SEALED, correctly, because this instrument never claimed to detect a third party's
# reconstruction inside the input it was told to read. The receipt discloses the permit
# contents so a stranger can judge that, instead of a detector pretending to.
node build-manifest.mjs --label control7b >/dev/null
PERMIT=$(jq -r .permit.host_path manifest.json)
cat >>"$PERMIT/prompt.txt" <<'PARAPHRASE'

Previous assessment (operator summary, 3 rows): two clearly problematic, one borderline.
PARAPHRASE
# rebuild AFTER the append, so the commitment covers the paraphrase: this is the
# "outside party put it in the input" case, which is disclosed, not detected
node build-manifest.mjs --label control7b >/dev/null
timeout 120 bash runner/run-cell.sh manifest.json receipts/control7b.json >/dev/null 2>&1
green control7b SEALED
chk "control7b discloses its bound" \
  "$(jq -r '.reasons|map(select(startswith("bound:")))|length' receipts/control7b.verdict.json)" "1"

echo
echo "controls: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

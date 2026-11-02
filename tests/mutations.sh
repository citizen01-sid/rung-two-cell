#!/usr/bin/env bash
# mutations.sh — does each decision in the instrument have a control that dies without it?
# A suite that stays green under mutation is a green check about nothing, which is the
# defect this instrument exists to answer.
#
# A mutant whose anchor does not apply is an ERROR, never a pass: an anchor that silently
# matches nothing would report "killed" or "survived" for a change that never happened.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
PET="$(mktemp -d "${TMPDIR:-/tmp}/rung2-mut-XXXXXX")"
killed=0; survived=0; errored=0

run_controls() { timeout 600 bash tests/negative-controls.sh >"$PET/out.txt" 2>&1; echo $?; }

mutate() { # name, file, old, new
  local name="$1" file="$2" old="$3" new="$4"
  local orig="$PET/$(basename "$file").orig"
  cp "$file" "$orig"
  if ! OLD="$old" NEW="$new" FILE="$file" python3 - <<'PY'
import os, pathlib, sys
p = pathlib.Path(os.environ["FILE"]); s = p.read_text()
old, new = os.environ["OLD"], os.environ["NEW"]
if old not in s:
    sys.exit(9)
p.write_text(s.replace(old, new, 1))
PY
  then
    cp "$orig" "$file"
    echo "  ERROR    $name — anchor did not match; mutation never applied"
    errored=$((errored+1)); return
  fi
  rc=$(run_controls)
  cp "$orig" "$file"
  if [ "$rc" -ne 0 ]; then
    echo "  killed   $name"; killed=$((killed+1))
  else
    echo "  SURVIVED $name — no control depends on this decision"; survived=$((survived+1))
  fi
}

echo "== baseline suite must be green before mutating"
if [ "$(run_controls)" -ne 0 ]; then echo "  ABORT: baseline not green"; tail -20 "$PET/out.txt"; exit 1; fi
echo "  ok baseline green"

echo "== mutants"
mutate "M1 drop the pre-dispatch tree check" runner/run-cell.sh \
  'if [ "$FORCE" != "1" ] && [ "$ACTUAL_TREE" != "$PERMIT_TREE" ]; then' \
  'if [ "$FORCE" = "never" ]; then'

mutate "M2 never call a named deny path readable" cell/probe.mjs \
  '      outcome = "READABLE";' \
  '      outcome = "ENOENT";'

mutate "M3 drop the canary token test" cell/probe.mjs \
  '  if (buf.includes(canary)) {' \
  '  if (false) {'

mutate "M4 drop the verbatim-line test" cell/probe.mjs \
  'if (denyLines.includes(createHash("sha256").update(line.trim()).digest("hex"))) {' \
  'if (false) {'

mutate "M5 treat an unreadable dir as absent" runner/verdict.mjs \
  '    return {
      verdict: "OPEN",
      reasons: [
        `${blind.length} director(ies) exist in the cell but denied entry' \
  '    return {
      verdict: "UNKNOWN",
      reasons: [
        `${blind.length} director(ies) exist in the cell but denied entry'

mutate "M6 ignore a readable deny path" runner/verdict.mjs \
  '  if (readable.length)' \
  '  if (false)'

mutate "M7 accept SEALED without the permit hash agreeing" runner/verdict.mjs \
  '  if (x.permit_matches_commit === true) reasons.push("permit tree matches the pre-dispatch commitment");' \
  '  if (true) reasons.push("permit tree matches the pre-dispatch commitment");'

mutate "M8 treat an undeclared mount as benign" runner/verdict.mjs \
  '  if (undeclared.length)' \
  '  if (false)'

mutate "M9 stop enumerating the mount table from inside" cell/probe.mjs \
  'receipt.undeclared_mounts = liveMounts.filter((p) => !declared.has(p)' \
  'receipt.undeclared_mounts = [].filter((p) => !declared.has(p)'

echo
echo "mutants: $killed killed, $survived survived, $errored errored"
rm -rf "$PET"
[ "$survived" -eq 0 ] && [ "$errored" -eq 0 ]

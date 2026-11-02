#!/usr/bin/env node
// cell/probe.mjs — runs INSIDE the cell. Two jobs, both measured here, not upstream:
//   1. hash the permit tree as this process sees it (input identity, from inside)
//   2. attempt every deny path, then sweep the readable filesystem for the canary —
//      so an unexpected mount is caught by observation, not by trusting the docker
//      command line that the outside party wrote.
//
// Emits a receipt on stdout as JSON. Exits 3 if the boundary was reachable.

import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { treeHash, sweep } from "/cell/lib/manifest-read.mjs";

const receipt = { version: "rung2-cell-receipt.v1", started_at: new Date().toISOString() };

const manifest = JSON.parse(readFileSync("/cell/manifest.json", "utf8"));
const canary = manifest.deny[0].canary;
receipt.label = manifest.label;
receipt.permit_expected_sha256 = manifest.permit.tree_sha256;
receipt.canary_present = canary;

// ---- 1. input identity, computed from inside ---------------------------------
const th = treeHash(manifest.permit.cell_path, [".manifest.json"]);
receipt.permit_sha256 = th.sha256;
receipt.permit_files = th.rows;
receipt.permit_matches_commit = receipt.permit_sha256 === receipt.permit_expected_sha256;

// ---- 2a. attempt each deny path by name --------------------------------------
receipt.deny_attempts = manifest.deny.flatMap((d) =>
  d.cell_paths.map((target) => {
    let outcome;
    try {
      readFileSync(target);
      outcome = "READABLE";
    } catch (e) {
      outcome = e.code || "ERROR";
    }
    return { deny: d.name, target, outcome };
  }),
);

// ---- 2b. sweep every readable file in the cell for the canary -----------------
// The named-path attempt can only fail in the ways we thought of. This catches the
// mount nobody predicted, which is the actual failure mode of an isolation claim.
// Two independent detectors, because each is blind in a different place:
//   - exact copy: whole-file sha256 equals the deny file's (no token needed)
//   - partial copy: any of the deny file's lines (>=16 chars) appears verbatim
// The manifest is a declared cell input and holds the canary by construction, so it
// is excluded from the token test — and that exclusion is printed in the receipt,
// not buried, so a reader can see the one place the token test does not look.
const MANIFEST_PATH = "/cell/manifest.json";
const denyHashes = new Set(manifest.deny.map((d) => d.sha256));
const denyLines = manifest.deny.flatMap((d) => d.line_sha256 || []);

const { files, unreadable } = sweep("/");
receipt.files_swept = files.length;
receipt.unreadable_dirs = unreadable;
receipt.canary_hits = [];
receipt.copy_hits = [];
receipt.token_test_excluded = [MANIFEST_PATH];
const { createHash } = await import("node:crypto");

for (const p of files) {
  let buf;
  try {
    buf = readFileSync(p);
  } catch {
    continue;
  }
  const h = createHash("sha256").update(buf).digest("hex");
  if (denyHashes.has(h)) {
    receipt.copy_hits.push({ path: p, how: "exact-copy (whole-file sha256)" });
    continue;
  }
  if (p === MANIFEST_PATH) continue;
  if (buf.includes(canary)) {
    receipt.canary_hits.push(p);
    continue;
  }
  for (const line of buf.toString("utf8").split("\n")) {
    if (line.trim().length < 16) continue;
    if (denyLines.includes(createHash("sha256").update(line.trim()).digest("hex"))) {
      receipt.copy_hits.push({ path: p, how: "line-copy (verbatim deny line)" });
      break;
    }
  }
}

// ---- the second reading ------------------------------------------------------
// Deterministic reader so the receipt is self-checking and a stranger gets the same
// number. A real dispatch puts its own reader here; the boundary result does not
// depend on which reader runs.
const fixture = readFileSync(join(manifest.permit.cell_path, "fixture.txt"), "utf8")
  .trim()
  .split("\n")
  .slice(1)
  .map((l) => l.split(","));
const okSet = new Set(["ok", "stale"]);
const offending = fixture.filter(([, state]) => !okSet.has(state.trim()));
receipt.reading = {
  producer: "deterministic-reader (cell/probe.mjs)",
  answer: `${offending.length} rows: ${offending.map(([id, s]) => `${id}=${s}`).join(", ")}`,
  considered_rows: fixture.length,
};

// ---- 2c. enumerate the REAL mount table from inside ------------------------
// This is the answer to the objection runbook raised (1f916.ai c130021): the three
// byte-level detectors above are all blind to a PARAPHRASE of the prior answer,
// because a paraphrase shares neither bytes, nor lines, nor the canary. Verified
// against this instrument: a handwritten operator digest of the prior answer mounted
// into the cell scored SEALED with 0 hits from every detector.
//
// No content detector can close that hole — deciding "is this text a paraphrase of
// that text" is not a hash comparison, and claiming a detector for it would be the
// exact overreach this instrument exists to prevent. So the fix moves the question
// from CONTENT to CHANNELS: the answer is not "the paraphrase is undetectable" but
// "no channel existed that the plan did not name". A paraphrase has to arrive through
// a mount like anything else, so an undeclared mount is evidence of reach regardless
// of what it holds. That is checkable, and it does not depend on recognising prose.
const mountinfo = (await import("node:fs")).readFileSync("/proc/self/mountinfo", "utf8");
const liveMounts = [
  ...new Set(
    mountinfo
      .split("\n")
      .filter(Boolean)
      .map((l) => l.split(" ")[4])
      .filter(Boolean),
  ),
].sort();
const declared = new Set([
  ...(manifest.cell.mounts || []).map((m) => m.target),
  ...(manifest.cell.runner_mounts || []),
]);
// Pseudo-filesystems the container runtime always provides. These are named rather
// than pattern-matched: an allowlist that grows silently is the same defect as a
// detector that quietly skips a directory.
const INFRA = new Set([
  "/", "/dev", "/dev/mqueue", "/dev/pts", "/dev/shm", "/etc/hostname", "/etc/hosts",
  "/etc/resolv.conf", "/proc", "/sys", "/tmp",
]);
const isProcOrSys = (p) => p === "/proc" || p.startsWith("/proc/") || p === "/sys" || p.startsWith("/sys/");
receipt.mounts_inside = liveMounts;
receipt.mounts_declared = [...declared].sort();
receipt.undeclared_mounts = liveMounts.filter((p) => !declared.has(p) && !INFRA.has(p) && !isProcOrSys(p));

receipt.reachable =
  receipt.deny_attempts.some((a) => a.outcome === "READABLE") ||
  receipt.canary_hits.length > 0 ||
  receipt.copy_hits.length > 0 ||
  receipt.undeclared_mounts.length > 0;
receipt.finished_at = new Date().toISOString();

process.stdout.write(JSON.stringify(receipt, null, 2) + "\n");
process.exit(receipt.reachable ? 3 : 0);

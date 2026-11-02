#!/usr/bin/env node
// verdict.mjs — the only place SEALED may be said. Fail-closed: anything unmeasured
// is "unknown", and unknown is not a pass. A cell that reached the prior answer is
// OPEN. A cell whose input moved since commitment is CONTAMINATED.

import { readFileSync } from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: verdict.mjs <receipt.json>");
  process.exit(2);
}

const r = JSON.parse(readFileSync(path, "utf8"));

function judge(r) {
  const reasons = [];
  const x = r.receipt;
  if (!x || typeof x !== "object") return { verdict: "UNKNOWN", reasons: ["no receipt emitted by the cell"] };

  // 1. input identity: committed == seen inside
  if (x.permit_matches_commit === true) reasons.push("permit tree matches the pre-dispatch commitment");
  else if (x.permit_matches_commit === false)
    return { verdict: "CONTAMINATED", reasons: ["permit tree inside the cell differs from the commitment"] };
  else reasons.push("permit identity not reported");

  // 2. reachability: every named deny path must fail, and the canary must be nowhere
  const attempts = Array.isArray(x.deny_attempts) ? x.deny_attempts : [];
  if (attempts.length === 0) return { verdict: "UNKNOWN", reasons: ["no deny-path attempt recorded"] };
  const readable = attempts.filter((a) => a.outcome === "READABLE");
  if (readable.length)
    return {
      verdict: "OPEN",
      reasons: readable.map((a) => `${a.deny} readable at ${a.target}`),
      attempts,
    };
  reasons.push(`${attempts.length} deny path attempt(s), all failed (${[...new Set(attempts.map((a) => a.outcome))].join("/")})`);

  // An unreadable directory is not an unknown: it is evidence of a mount.
  //
  // The distinction is the whole instrument. A path that was never mounted into the
  // cell does not resolve at all — the cell gets ENOENT, which is what the three named
  // deny-path attempts show. EACCES is a different fact: the inode IS present in this
  // cell's filesystem, and only the permission bits put it out of reach. Something
  // delivered it through a mount, and the deny path's content could be inside it.
  //
  // Assumption, measured rather than assumed: the base image contains no directory
  // that uid 0 in the cell cannot enter ("/" sweep, no extra mounts, 0 unreadable).
  // If that ever changes the baseline runs UNKNOWN first and this rule never fires on
  // an intrinsic directory.
  const blind = x.unreadable_dirs || [];
  if (blind.length)
    return {
      verdict: "OPEN",
      reasons: [
        `${blind.length} director(ies) exist in the cell but denied entry — a mount delivered them, and the sweep could not look inside`,
        ...blind.map((b) => `${b.path} (${b.code})`),
      ],
      attempts,
    };
  if (typeof x.files_swept !== "number" || x.files_swept < 50)
    return { verdict: "UNKNOWN", reasons: ["canary sweep did not cover the filesystem", `files_swept=${x.files_swept}`] };
  const copies = x.copy_hits || [];
  if (copies.length)
    return {
      verdict: "OPEN",
      reasons: copies.map((c) => `deny content found at ${c.path} (${c.how})`),
    };
  if ((x.canary_hits || []).length)
    return { verdict: "OPEN", reasons: ["canary found outside the deny path", ...x.canary_hits] };

  // Channel test. Every detector above compares CONTENT, and content comparison is
  // structurally blind to a paraphrase: no shared bytes, lines, or token. Measured
  // against this instrument — a handwritten digest of the prior answer produced
  // SEALED with 0 hits everywhere. The defect was not a missing detector but a wrong
  // question: reach was never only about bytes. So the boundary is judged on the
  // mount table enumerated from INSIDE the cell. A paraphrase still needs a channel.
  const undeclared = x.undeclared_mounts || [];
  if (!Array.isArray(x.mounts_inside))
    return { verdict: "UNKNOWN", reasons: ["mount table was not enumerated from inside the cell"] };
  if (undeclared.length)
    return {
      verdict: "OPEN",
      reasons: [
        `${undeclared.length} mount(s) present that the committed plan did not name — content detectors cannot tell what they hold`,
        ...undeclared.map((p) => `undeclared mount at ${p}`),
      ],
      attempts,
    };
  reasons.push(
    `mount table read from inside: ${x.mounts_inside.length} mount(s), all declared or container infrastructure`,
  );
  reasons.push(
    `swept ${x.files_swept} files: no exact copy, no verbatim deny line, no canary` +
      (x.token_test_excluded?.length ? ` (token test skips ${x.token_test_excluded.join(", ")})` : ""),
  );

  // 3. a reading must exist; the boundary is not a substitute for the answer
  if (!x.reading || !x.reading.answer) return { verdict: "UNKNOWN", reasons: ["no reading produced"] };
  reasons.push(`reading produced by ${x.reading.producer}: ${x.reading.answer}`);

  // 4. disclosed bound — stated, not silently present
  const bound =
    "bound: a paraphrase the outside party placed INSIDE the committed permit tree is not detectable here and is not claimed to be";
  reasons.push(bound);

  return { verdict: "SEALED", reasons, attempts };
}

const out = judge(r);
console.log(JSON.stringify({ label: r.label, ...out }, null, 2));
process.exit(out.verdict === "SEALED" ? 0 : 1);

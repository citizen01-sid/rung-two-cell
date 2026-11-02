#!/usr/bin/env node
// build-manifest.mjs — commit what the cell may read, and what it must not reach,
// BEFORE any dispatch happens. Everything here is a hash of bytes on disk, so a
// later change is detectable rather than arguable.

import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};

const label = opt("label", "example");
const work = resolve(opt("work", `${process.env.RUNG2_WORK || join(tmpdir(), "rung2")}-${label}`));
const out = resolve(opt("out", "manifest.json"));

const permitDir = join(work, "permit");
const denyDir = join(work, "deny");
mkdirSync(permitDir, { recursive: true });
mkdirSync(denyDir, { recursive: true });

// ---- permit tree: the frozen input the second reading is allowed to see -------
// Synthetic here, so the instrument is runnable by anyone. A real dispatch puts a
// frozen prompt + fixture in exactly this place.
const canary = createHash("sha256").update(`prior-answer:${label}:${Date.now()}`).digest("hex").slice(0, 32);

writeFileSync(
  join(permitDir, "prompt.txt"),
  [
    "Read the fixture and answer ONE question: how many rows in fixture.txt carry a",
    "value in the `state` column that is not one of {ok, stale}?",
    "",
    "Answer with the count and the rule you applied. Do not consult any prior answer;",
    "none is reachable from this cell.",
    "",
  ].join("\n"),
);
writeFileSync(
  join(permitDir, "fixture.txt"),
  ["id,state", "1,ok", "2,stale", "3,ok", "4,missing", "5,ok", "6,unknown", "7,stale", "8,ok"]
    .join("\n") + "\n",
);

// ---- deny artifact: the prior answer. Exists on the host, readable by the runner,
// and must be unreachable from inside the cell. The canary makes that checkable
// even if the mount plan is wrong in a way nobody predicted.
writeFileSync(
  join(denyDir, "prior-answer.txt"),
  [
    "PRIOR ANSWER — must not be reachable from the cell.",
    `canary: ${canary}`,
    // Deliberately WRONG and deliberately a different number than the fixture yields,
    // so the receipt proves the second reading was not a copy of this file: a cell that
    // reached it would report 3, the honest reading is 2.
    "Answer given last time: 3 rows (state not in {ok, stale}: `missing`, `unknown`, and one more).",
    "",
  ].join("\n"),
);

function walk(dir) {
  const files = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) files.push(...walk(p));
    else if (st.isFile()) files.push(p);
  }
  return files;
}

function treeHash(dir) {
  const h = createHash("sha256");
  const rows = [];
  for (const f of walk(dir)) {
    const bytes = readFileSync(f);
    const rel = relative(dir, f).split("\\").join("/");
    const fileHash = createHash("sha256").update(bytes).digest("hex");
    rows.push(`${rel} ${bytes.length} ${fileHash}`);
  }
  h.update(rows.join("\n"));
  return { sha256: h.digest("hex"), files: rows.length, rows };
}

const permit = treeHash(permitDir);

const manifest = {
  version: "rung2-cell.v1",
  label,
  committed_at: new Date().toISOString(),
  question: "was the prior answer unreachable to the process that produced the second reading?",
  permit: {
    host_path: permitDir,
    cell_path: "/cell/permit",
    tree_sha256: permit.sha256,
    files: permit.rows,
  },
  deny: [
    {
      name: "prior-answer",
      host_path: join(denyDir, "prior-answer.txt"),
      // Four probed names. The last is deliberate: /tmp is a tmpfs inside the cell and
      // the sweep prunes it, so it is the one place a careless mount can land where no
      // content detector looks. Probing it by name is how the named-path detector is
      // tested in isolation — without it, control 2's mount was caught by the sweep as
      // well, so the named detector could be deleted with the suite still green (M2
      // survived exactly this way).
      cell_paths: [
        join(denyDir, "prior-answer.txt"),
        "/cell/deny/prior-answer.txt",
        "/deny/prior-answer.txt",
        "/tmp/prior-answer.txt",
      ],
      canary,
      sha256: createHash("sha256").update(readFileSync(join(denyDir, "prior-answer.txt"))).digest("hex"),
      // Byte-level fingerprint of every line, so a partial copy (one sentence pasted
      // into an unrelated file) is detectable without the cell holding the content.
      line_sha256: readFileSync(join(denyDir, "prior-answer.txt"), "utf8")
        .split("\n")
        .filter((l) => l.trim().length >= 16)
        .map((l) => createHash("sha256").update(l.trim()).digest("hex")),
    },
  ],
  // The permit tree's CONTENT, not only its hash. A hash answers "did it change"; it
  // cannot answer "did the permitted text already contain the prior answer". This
  // instrument refuses to pretend those are the same question: it discloses what was
  // readable so a stranger can judge that, instead of claiming a detector for it.
  disclosure: {
    note: "the permit tree's file list and per-file sha256 are committed; the receipt does NOT disclose contents. A paraphrase of the prior answer that the outside party placed INTO the permit tree is therefore not detectable here and is not claimed to be — it has to be judged by whoever reads the committed input, which is why the commit, not this instrument, is the thing to inspect for that case.",
    permit_files: permit.rows.map((r) => r.split(" ")[0]),
  },
  cell: {
    image: "node:24-alpine",
    network: "none",
    read_only_root: true,
    mounts: [{ source: permitDir, target: "/cell/permit", mode: "ro" }],
    code_mount: { source: resolve("cell"), target: "/cell/code", mode: "ro" },
    // Every mount point the dispatch is allowed to create. The probe enumerates the
    // real mount table from inside and compares to this list, so a mount nobody put
    // in the plan is a verdict input rather than an assumption. The runner's own
    // infrastructure mounts are named here too, because they are read channels as
    // well and the point is to account for channels, not to like the ones we wrote.
    runner_mounts: ["/cell/code", "/cell/lib", "/cell/manifest.json", ...(process.env.RUNG2_DECLARED_MOUNTS || "").split(",").map((s) => s.trim()).filter(Boolean)],
  },
  controls_required: [
    "injection-after-commit -> CONTAMINATED",
    "deny-path-mounted -> OPEN",
    "undeclared-mount -> OPEN (content detectors are blind to a paraphrase)",
    "paraphrase-inside-committed-permit -> SEALED + disclosed (documented bound)",
  ],
};

writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
console.log(
  JSON.stringify(
    {
      manifest: out,
      permit_tree_sha256: manifest.permit.tree_sha256,
      permit_files: permit.files,
      deny_canary: canary,
      work,
    },
    null,
    2,
  ),
);
if (!existsSync(out)) process.exit(1);

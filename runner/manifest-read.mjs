#!/usr/bin/env node
// runner/manifest-read.mjs — ONE implementation of both the tree hash and the
// filesystem sweep, shared by the outside party (pre-dispatch) and inside the cell.
// Two implementations of "the hash" would be two operands, and this instrument
// exists precisely to avoid asking a reader to reconcile two.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// A sweep that hangs is indistinguishable from a sweep that found nothing, so
// pseudo-filesystems are pruned during traversal, not filtered afterwards.
const PRUNE = new Set(["/proc", "/sys", "/dev", "/run", "/tmp"]);

export function walk(dir, { acc = [], maxBytes = Infinity, unreadable = [] } = {}) {
  let names;
  try {
    names = readdirSync(dir);
  } catch (e) {
    // A directory the sweep cannot enter is NOT an empty directory. Silently skipping
    // it is how an isolation claim turns green while the thing it protects sits in an
    // unreadable mount. Recorded, and the verdict refuses to call that sealed.
    unreadable.push({ path: dir, code: e.code || "ERROR" });
    return acc;
  }
  for (const name of names.sort()) {
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p, { throwIfNoEntry: false });
    } catch {
      continue;
    }
    if (!st) continue;
    if (st.isDirectory()) {
      if (PRUNE.has(p)) continue;
      walk(p, { acc, maxBytes, unreadable });
    } else if (st.isFile() && st.size <= maxBytes) {
      acc.push(p);
    }
  }
  return acc;
}

export function treeHash(dir, skip = []) {
  const rows = walk(dir)
    .filter((p) => !skip.includes(relative(dir, p).split("\\").join("/")))
    .map((p) => {
      const bytes = readFileSync(p);
      const rel = relative(dir, p).split("\\").join("/");
      return `${rel} ${bytes.length} ${createHash("sha256").update(bytes).digest("hex")}`;
    });
  return { sha256: createHash("sha256").update(rows.join("\n")).digest("hex"), rows };
}

// Files readable from this process, with a size ceiling: the deny artifact is a
// text record, so an 8 MiB cap costs nothing and keeps the sweep bounded.
export function sweep(root = "/", maxBytes = 8 * 1024 * 1024) {
  const unreadable = [];
  const files = walk(root, { maxBytes, unreadable });
  return { files, unreadable };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [manifestPath] = process.argv.slice(2);
  const m = JSON.parse(readFileSync(manifestPath, "utf8"));
  const actual = treeHash(m.permit.host_path, [".manifest.json"]);
  process.stdout.write(
    [
      `PERMIT_HOST=${JSON.stringify(m.permit.host_path)}`,
      `PERMIT_TREE=${JSON.stringify(m.permit.tree_sha256)}`,
      `ACTUAL_TREE=${JSON.stringify(actual.sha256)}`,
      `IMAGE=${JSON.stringify(m.cell.image)}`,
      `NETWORK=${JSON.stringify(m.cell.network)}`,
      `CODE_HOST=${JSON.stringify(m.cell.code_mount.source)}`,
      `LABEL=${JSON.stringify(m.label)}`,
    ].join("\n") + "\n",
  );
}

#!/usr/bin/env node
/**
 * Owner: scripts/classify-extension-fs-imports
 *
 * E.5 stratification — classifies every node:fs import under
 * `extensions/<id>/src/**` as one of:
 *
 *   - runtime    — the import sits on a code path the gateway hits
 *                  while serving a session (filename matches one of
 *                  RUNTIME_PATTERNS). These are the codemod targets
 *                  for E.5 batches.
 *   - setup      — the import is in setup/doctor/discovery/onboarding
 *                  code. Lower priority for the codemod because these
 *                  paths run at CLI / install time, not in-session.
 *   - other      — neither pattern matches. Hand-review before
 *                  classifying. Operator may choose to codemod these
 *                  if they touch live session paths.
 *
 * The classification heuristic is filename-based (deliberately
 * lightweight). A misclassification surfaces in PR review during
 * the E.5 codemod batches and can be corrected in the same diff
 * that lands the swap.
 *
 * Output (default, JSON when --json):
 *   counts {runtime, setup, other, total}
 *   buckets per category (relativePath:line excerpt)
 *
 * Usage:
 *   node scripts/classify-extension-fs-imports.mjs
 *   node scripts/classify-extension-fs-imports.mjs --json
 *   node scripts/classify-extension-fs-imports.mjs --category runtime
 *
 * @stable
 */
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const RUNTIME_PATTERNS = [
  /runtime/i,
  /transport/i,
  /tool/i,
  /service/i,
  /register/i,
  /oauth/i,
  /provider/i,
  /channel/i,
  /agent/i,
  /session/i,
];

const SETUP_PATTERNS = [
  /setup/i,
  /doctor/i,
  /discover/i,
  /onboard/i,
  /install/i,
  /probe/i,
  /audit/i,
  /\.cli\./i,
  /cli-/i,
  /-cli\./i,
];

function classify(relativePath) {
  if (SETUP_PATTERNS.some((rx) => rx.test(relativePath))) {
    return "setup";
  }
  if (RUNTIME_PATTERNS.some((rx) => rx.test(relativePath))) {
    return "runtime";
  }
  return "other";
}

function loadFsHits() {
  const banScript = path.join(REPO_ROOT, "scripts", "check-extension-fetch-fs.mjs");
  const raw = execFileSync("node", [banScript, "--json"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  const data = JSON.parse(raw);
  return (data.hits ?? []).filter((hit) => hit.match === "node:fs");
}

function main() {
  const argv = process.argv.slice(2);
  const json = argv.includes("--json");
  const category = (() => {
    const idx = argv.indexOf("--category");
    return idx >= 0 ? argv[idx + 1] : undefined;
  })();
  const hits = loadFsHits();
  const buckets = { runtime: [], setup: [], other: [] };
  for (const hit of hits) {
    const bucket = classify(hit.relativePath);
    buckets[bucket].push(hit);
  }
  const counts = {
    runtime: buckets.runtime.length,
    setup: buckets.setup.length,
    other: buckets.other.length,
    total: hits.length,
  };
  if (json) {
    process.stdout.write(`${JSON.stringify({ counts, buckets }, null, 2)}\n`);
    return;
  }
  process.stdout.write(
    `extension fs-import stratification:\n` +
      `  runtime: ${counts.runtime}\n` +
      `  setup:   ${counts.setup}\n` +
      `  other:   ${counts.other}\n` +
      `  total:   ${counts.total}\n`,
  );
  if (category && buckets[category]) {
    process.stdout.write(`\n--- ${category} bucket ---\n`);
    for (const hit of buckets[category]) {
      process.stdout.write(`  ${hit.relativePath}:${hit.line} ${hit.excerpt}\n`);
    }
  }
}

main();

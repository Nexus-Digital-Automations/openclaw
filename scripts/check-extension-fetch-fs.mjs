#!/usr/bin/env node
/**
 * Owner: scripts/check-extension-fetch-fs
 *
 * E.6 gate — refuses bundled-plugin source files that bypass the
 * SDK's capability-gated HTTP + FS wrappers by using bare `fetch(`
 * or by importing `node:fs` / `node:fs/promises` directly.
 *
 * Why a custom script and not oxlint: oxlint does not yet support
 * `no-restricted-imports` or `no-restricted-globals` rules. Until
 * upstream lands those, this script provides the equivalent
 * coverage scoped narrowly to `extensions/**\/src/**`. When oxlint
 * grows the rules, replace this script with an .oxlintrc.json
 * override and delete this file.
 *
 * Hard-blocks once E.2 (fetch codemod) and E.5 (fs codemod) finish
 * landing. Before then the script reports the live count so
 * operators can track the codemod's progress; CI flips from advisory
 * to enforcing via the --strict flag in the same commit that
 * declares the codemods done.
 *
 * Usage:
 *   node scripts/check-extension-fetch-fs.mjs            # advisory print
 *   node scripts/check-extension-fetch-fs.mjs --strict   # exit 1 on hit
 *   node scripts/check-extension-fetch-fs.mjs --json     # JSON output
 *
 * @stable
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSIONS_DIR = path.join(REPO_ROOT, "extensions");

const BARE_FETCH_PATTERN = /\bfetch\s*\(/;
const NODE_FS_IMPORT_PATTERN = /from\s+["']node:fs(\/promises)?["']/;

// Patterns that match a SUPERFICIAL `fetch(` but aren't a bare global call.
// Each is checked on the line BEFORE we count a hit so the ban gate stays
// honest about real production fetch calls.
const FETCH_FALSE_POSITIVE_PATTERNS = [
  /\.\s*fetch\s*\(/, // foo.fetch(...) — method call on an object, not the global
  /\bparams\.fetch\s*\(/, // DI'd fetch from caller params
  /\bglobalThis\.fetch\s*\(/, // explicit globalThis route — usually a test injector
  /^\s*(\/\/|\*|\/\*)/, // line is a comment
  /\*\s*[A-Za-z]/, // continuation of JSDoc text (e.g. ` * fetch() ...`)
  /async\s+fetch\s*\(/, // class method declaration with the literal name "fetch"
  /\bfetch\s*\(\)\s*:\s*Promise/, // type literal `fetch(): Promise<...>`
  /[`"']\s*[-#]\s*fetch\s*\(/, // fetch( inside a bash-script template literal
  /^\s*-\s+fetch\s*\(/, // bash heredoc line starting with `- fetch(` (subprocess script body)
];

// Files known to embed Node subprocess scripts inside template literals. The
// `fetch(...)` inside those literals runs in a spawned child Node process, not
// the openclaw process — so pluginFetch can't intercept it. Each entry is a
// substring of relativePath; the line-scan still surfaces these for review but
// the strict-mode exit code does not flag them.
const SUBPROCESS_DRIVER_FILES = [
  "extensions/qa-lab/src/docker-harness.ts",
  "extensions/qa-lab/src/mantis/slack-desktop-smoke.runtime.ts",
  "extensions/qa-lab/src/mantis/telegram-desktop-builder.runtime.ts",
];

const IGNORED_BASENAME_SUFFIXES = [
  ".test.ts",
  ".test-helpers.ts",
  ".test-harness.ts",
  ".e2e-harness.ts",
  ".spec.ts",
];

const IGNORED_PATH_SEGMENTS = ["/test-support/"];

async function findExtensionSourceFiles() {
  const out = [];
  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "dist") {
          continue;
        }
        await walk(abs);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      if (!abs.endsWith(".ts")) {
        continue;
      }
      if (IGNORED_BASENAME_SUFFIXES.some((suffix) => abs.endsWith(suffix))) {
        continue;
      }
      if (IGNORED_PATH_SEGMENTS.some((segment) => abs.includes(segment))) {
        continue;
      }
      out.push(abs);
    }
  }
  const extensionEntries = await fs.readdir(EXTENSIONS_DIR, { withFileTypes: true });
  for (const entry of extensionEntries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const src = path.join(EXTENSIONS_DIR, entry.name, "src");
    await walk(src);
  }
  return out;
}

async function scanFile(absPath) {
  const contents = await fs.readFile(absPath, "utf8").catch(() => "");
  if (!contents) {
    return [];
  }
  const relativePath = path.relative(REPO_ROOT, absPath);
  const hits = [];
  const lines = contents.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (BARE_FETCH_PATTERN.test(line) && !isFetchFalsePositive(line)) {
      hits.push({ relativePath, line: index + 1, match: "fetch", excerpt: line.trim() });
    }
    if (NODE_FS_IMPORT_PATTERN.test(line)) {
      hits.push({ relativePath, line: index + 1, match: "node:fs", excerpt: line.trim() });
    }
  }
  return hits;
}

function isFetchFalsePositive(line) {
  return FETCH_FALSE_POSITIVE_PATTERNS.some((pattern) => pattern.test(line));
}

async function main() {
  const argv = new Set(process.argv.slice(2));
  const strict = argv.has("--strict");
  const json = argv.has("--json");
  const files = await findExtensionSourceFiles();
  const allHits = [];
  for (const file of files) {
    allHits.push(...(await scanFile(file)));
  }
  const blockingHits = allHits.filter(
    (hit) => !SUBPROCESS_DRIVER_FILES.some((driverPath) => hit.relativePath.includes(driverPath)),
  );
  const fetchCount = blockingHits.filter((hit) => hit.match === "fetch").length;
  const fsCount = blockingHits.filter((hit) => hit.match === "node:fs").length;
  const subprocessDriverCount = allHits.length - blockingHits.length;
  if (json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          scanned: files.length,
          fetchHits: fetchCount,
          fsHits: fsCount,
          subprocessDriverHits: subprocessDriverCount,
          hits: blockingHits,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    process.stdout.write(
      `extension fetch/fs ban: scanned=${files.length} fetchHits=${fetchCount} fsHits=${fsCount} subprocessDriverHits=${subprocessDriverCount}\n`,
    );
    if (blockingHits.length > 0 && !strict) {
      process.stdout.write(
        `advisory mode — first 20 blocking hits:\n${blockingHits
          .slice(0, 20)
          .map((hit) => `  ${hit.relativePath}:${hit.line} [${hit.match}] ${hit.excerpt}`)
          .join("\n")}\n`,
      );
    }
  }
  if (strict && blockingHits.length > 0) {
    process.stdout.write(
      `\nSTRICT MODE: ${blockingHits.length} hit(s) — see plugin-sdk/http-guard-runtime + plugin-sdk/fs-guard-runtime for the gated alternatives.\n`,
    );
    process.exit(1);
  }
}

await main();

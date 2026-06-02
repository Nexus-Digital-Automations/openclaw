#!/usr/bin/env node
/**
 * Owner: scripts/observe-bundled-plugin-hooks
 *
 * C.1 — backfill-tooling discovery pass for the capability manifest
 * milestone (C.4). Enumerates every bundled plugin manifest under
 * extensions/ and emits a JSON summary of which plugins declare
 * `capabilities.hooks` and which do not. Operators read the report to
 * size the per-plugin backfill workload and to verify post-C.4 that
 * every plugin declares its hook surface before the strict-enforce
 * flip (C.6).
 *
 * The tool does NOT mutate manifests — it only observes. Hand review
 * per plugin is still required (per the v3 plan decision) because
 * static observation cannot tell intentional dev-only hook
 * registrations from production-required ones.
 *
 * Output shape (JSON to stdout):
 *   {
 *     scannedManifests: number,
 *     declaringHooks: number,
 *     missingDeclaration: number,
 *     plugins: [
 *       { id, manifestPath, declaredHooks: string[] | "missing" }
 *     ]
 *   }
 *
 * Usage:
 *   node scripts/observe-bundled-plugin-hooks.mjs                 # JSON
 *   node scripts/observe-bundled-plugin-hooks.mjs --summary       # 1-line
 *   node scripts/observe-bundled-plugin-hooks.mjs --gaps-only     # only undeclared
 *
 * Exit codes:
 *   0 — observation completed
 *   1 — manifest parse error or filesystem failure
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSIONS_DIR = path.join(REPO_ROOT, "extensions");

async function listBundledPluginManifests() {
  const entries = await fs.readdir(EXTENSIONS_DIR, { withFileTypes: true });
  const manifests = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const manifestPath = path.join(EXTENSIONS_DIR, entry.name, "openclaw.plugin.json");
    try {
      await fs.access(manifestPath);
      manifests.push({ id: entry.name, manifestPath });
    } catch {
      // Not every directory under extensions/ is a bundled plugin
      // (some are test fixtures or build artifacts). Silently skip.
    }
  }
  return manifests;
}

async function readManifestHookDeclaration(manifestPath) {
  const raw = await fs.readFile(manifestPath, "utf8");
  const parsed = JSON.parse(raw);
  const declared = parsed?.capabilities?.hooks;
  if (!Array.isArray(declared)) {
    return "missing";
  }
  return declared.filter((entry) => typeof entry === "string");
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const manifests = await listBundledPluginManifests();
  const observations = [];
  for (const { id, manifestPath } of manifests) {
    try {
      const declaredHooks = await readManifestHookDeclaration(manifestPath);
      observations.push({ id, manifestPath, declaredHooks });
    } catch (err) {
      console.error(`failed to parse ${manifestPath}: ${String(err)}`);
      process.exitCode = 1;
    }
  }
  const summary = {
    scannedManifests: observations.length,
    declaringHooks: observations.filter(
      (entry) => Array.isArray(entry.declaredHooks) && entry.declaredHooks.length > 0,
    ).length,
    missingDeclaration: observations.filter((entry) => entry.declaredHooks === "missing").length,
    plugins: args.has("--gaps-only")
      ? observations.filter((entry) => entry.declaredHooks === "missing")
      : observations,
  };
  if (args.has("--summary")) {
    console.log(
      `bundled plugins: ${summary.scannedManifests} total, ${summary.declaringHooks} declare capabilities.hooks, ${summary.missingDeclaration} missing`,
    );
    return;
  }
  console.log(JSON.stringify(summary, null, 2));
}

try {
  await main();
} catch (err) {
  console.error(String(err));
  process.exit(1);
}

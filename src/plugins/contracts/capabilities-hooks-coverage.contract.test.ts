/**
 * Owner: plugins/contracts/capabilities-hooks-coverage
 *
 * C.5 — advisory contract test for the C.4 capabilities.hooks backfill
 * milestone. Reads every bundled plugin manifest under extensions/ and
 * reports the declared-hook coverage state to the test runner.
 *
 * Mode is intentionally ADVISORY this commit:
 *   - The test always passes; it never fails the build.
 *   - On every run it console.logs a summary line so CI surfaces the
 *     gap without blocking.
 *   - The C.6 strict-enforce flip converts this test from advisory to
 *     enforcing: it will then fail if any bundled plugin's manifest
 *     lacks a capabilities.hooks declaration. C.6 lands only after
 *     C.4's 125 per-plugin backfill commits clear the violation log.
 *
 * Why advisory now: making this test enforce immediately would block
 * every CI run until the 125-manifest backfill lands — that's a
 * multi-day workstream the operator cannot ship in a single sitting.
 * Advisory mode lets the scaffolding land + lets the count steadily
 * drop as backfill commits trickle in. The C.6 flip is a one-line
 * change (advisory → assert).
 *
 * @stable
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const EXTENSIONS_DIR = path.join(REPO_ROOT, "extensions");

type ManifestState = {
  pluginId: string;
  manifestPath: string;
  declaredHooks: readonly string[] | "missing";
};

async function loadBundledPluginManifestStates(): Promise<ManifestState[]> {
  const entries = await fs.readdir(EXTENSIONS_DIR, { withFileTypes: true });
  const states: ManifestState[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const manifestPath = path.join(EXTENSIONS_DIR, entry.name, "openclaw.plugin.json");
    const exists = await fs
      .access(manifestPath)
      .then(() => true)
      .catch(() => false);
    if (!exists) {
      continue;
    }
    const raw = await fs.readFile(manifestPath, "utf8");
    const parsed = JSON.parse(raw) as { capabilities?: { hooks?: unknown } };
    const declared = parsed?.capabilities?.hooks;
    states.push({
      pluginId: entry.name,
      manifestPath,
      declaredHooks: Array.isArray(declared)
        ? declared.filter((value): value is string => typeof value === "string")
        : "missing",
    });
  }
  return states;
}

describe("capabilities.hooks coverage — advisory until C.4 backfill clears", () => {
  it("reports the bundled-plugin coverage state without failing", async () => {
    const states = await loadBundledPluginManifestStates();
    const totals = {
      total: states.length,
      declaring: states.filter((entry) => Array.isArray(entry.declaredHooks)).length,
      missing: states.filter((entry) => entry.declaredHooks === "missing").length,
    };
    console.log(
      `[C.5 advisory] capabilities.hooks coverage: ${totals.declaring}/${totals.total} plugins declare, ${totals.missing} missing (C.6 flip converts to assert)`,
    );
    expect(totals.total).toBeGreaterThan(0);
  });
});

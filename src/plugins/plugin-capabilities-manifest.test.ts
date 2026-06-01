/**
 * Owner: plugins/plugin-capabilities-manifest.test
 *
 * Spec: F.4 — load-time capability hydration. Proves the hook hard-block
 * survives a gateway restart: hydration re-reads the security capability
 * surface from openclaw.plugin.json (it is NOT in memory after manifest load)
 * and stamps the enforcement mode WITHOUT any install call.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginInstallRecord } from "../config/types.plugins.js";
import {
  clearPluginCapabilitiesForTests,
  getPluginCapabilities,
  getPluginCapabilityEnforcement,
} from "./capabilities.js";
import {
  hydratePluginCapabilityGate,
  loadPluginCapabilitiesFromDir,
} from "./plugin-capabilities-manifest.js";

const PLUGIN_ID = "plugin-under-test";
const tempDirs: string[] = [];

function makePluginDir(manifest: string | null): string {
  const dir = mkdtempSync(path.join(tmpdir(), "openclaw-caps-"));
  tempDirs.push(dir);
  if (manifest !== null) {
    writeFileSync(path.join(dir, "openclaw.plugin.json"), manifest, "utf8");
  }
  return dir;
}

const enforcedRecord: PluginInstallRecord = { source: "npm", capabilityGate: "enforced" };

afterEach(() => {
  clearPluginCapabilitiesForTests();
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("loadPluginCapabilitiesFromDir", () => {
  it("returns no capabilities when the manifest is absent (grandfather)", () => {
    const dir = makePluginDir(null);
    expect(loadPluginCapabilitiesFromDir(dir)).toEqual({ ok: true });
  });

  it("normalizes the capabilities block when present", () => {
    const dir = makePluginDir(JSON.stringify({ capabilities: { hooks: ["before_tool_call"] } }));
    const result = loadPluginCapabilitiesFromDir(dir);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.capabilities?.hooks).toEqual(["before_tool_call"]);
    }
  });

  it("fails on malformed JSON so the install gate can refuse", () => {
    const dir = makePluginDir("{ not json");
    const result = loadPluginCapabilitiesFromDir(dir);
    expect(result.ok).toBe(false);
  });
});

describe("hydratePluginCapabilityGate — restart hydration without an install call", () => {
  it("populates capabilities + enforces a stamped external install", () => {
    const dir = makePluginDir(JSON.stringify({ capabilities: { hooks: ["before_prompt_build"] } }));
    hydratePluginCapabilityGate({
      pluginId: PLUGIN_ID,
      rootDir: dir,
      origin: "global",
      installRecord: enforcedRecord,
    });
    expect(getPluginCapabilities(PLUGIN_ID)?.hooks).toEqual(["before_prompt_build"]);
    expect(getPluginCapabilityEnforcement(PLUGIN_ID)).toBe("enforced");
  });

  it("grandfathers a bundled plugin even when the record is stamped (F.2 external-only)", () => {
    const dir = makePluginDir(JSON.stringify({ capabilities: { hooks: ["before_prompt_build"] } }));
    hydratePluginCapabilityGate({
      pluginId: PLUGIN_ID,
      rootDir: dir,
      origin: "bundled",
      installRecord: enforcedRecord,
    });
    expect(getPluginCapabilityEnforcement(PLUGIN_ID)).toBe("grandfathered");
  });

  it("grandfathers an external plugin with no stamp (F.4 grandfather existing)", () => {
    const dir = makePluginDir(JSON.stringify({ capabilities: { hooks: ["before_prompt_build"] } }));
    hydratePluginCapabilityGate({
      pluginId: PLUGIN_ID,
      rootDir: dir,
      origin: "global",
      installRecord: { source: "npm" },
    });
    expect(getPluginCapabilityEnforcement(PLUGIN_ID)).toBe("grandfathered");
  });

  it("logs and grandfathers a malformed manifest rather than throwing", () => {
    const dir = makePluginDir("{ not json");
    const warn = vi.fn();
    expect(() =>
      hydratePluginCapabilityGate({
        pluginId: PLUGIN_ID,
        rootDir: dir,
        origin: "global",
        installRecord: enforcedRecord,
        logger: { warn },
      }),
    ).not.toThrow();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(JSON.parse(warn.mock.calls[0][0]).event).toBe("plugin.capability.hydrate_failed");
    expect(getPluginCapabilityEnforcement(PLUGIN_ID)).toBeUndefined();
  });
});

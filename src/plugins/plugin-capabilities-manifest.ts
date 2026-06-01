// Owner: plugins/capabilities. Reads + normalizes the security `capabilities`
// block from a plugin directory's `openclaw.plugin.json`, and hydrates the
// runtime capability + enforcement registries at load. Shared by the P1.7
// install-signing gate (refuse-on-malformed) and the loader's F.4 load-time
// hydration pass (best-effort) so both parse the manifest the same way.
//
// Sync I/O on purpose: the loader's per-plugin path is synchronous (module
// load runs through `runPluginRegisterSync`), so hydration reads one small
// manifest synchronously rather than forcing the load loop async.

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { PluginInstallRecord } from "../config/types.plugins.js";
import {
  normalizeCapabilitiesManifest,
  type PluginCapabilities,
  setPluginCapabilities,
  setPluginCapabilityEnforcement,
} from "./capabilities.js";
import type { PluginOrigin } from "./plugin-origin.types.js";

export type LoadPluginCapabilitiesResult =
  | { ok: true; capabilities?: PluginCapabilities }
  | { ok: false; reason: string };

/**
 * Read + normalize the `capabilities` block from `<dir>/openclaw.plugin.json`.
 * A missing manifest or absent `capabilities` field is `{ ok: true }` with no
 * capabilities (grandfather). Malformed JSON / wrong shape is `{ ok: false }`
 * so the install gate can refuse; load-time callers treat it best-effort.
 *
 * @stable
 */
export function loadPluginCapabilitiesFromDir(dir: string): LoadPluginCapabilitiesResult {
  const manifestPath = path.join(dir, "openclaw.plugin.json");
  if (!existsSync(manifestPath)) {
    return { ok: true };
  }
  let raw: string;
  try {
    raw = readFileSync(manifestPath, "utf8");
  } catch (err) {
    return { ok: false, reason: `failed to read openclaw.plugin.json: ${String(err)}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, reason: `openclaw.plugin.json is not valid JSON: ${String(err)}` };
  }
  if (!parsed || typeof parsed !== "object") {
    return { ok: false, reason: "openclaw.plugin.json root must be an object" };
  }
  const capabilitiesField = (parsed as Record<string, unknown>).capabilities;
  if (capabilitiesField === undefined) {
    return { ok: true };
  }
  const capabilities = normalizeCapabilitiesManifest(capabilitiesField);
  if (capabilities === null) {
    return { ok: false, reason: "openclaw.plugin.json capabilities must be an object" };
  }
  return { ok: true, capabilities };
}

/**
 * Populate the runtime capability + enforcement registries for one plugin at
 * load. The security capability surface is not in memory after manifest load
 * (only the install gate parses it), so it must be re-read here or the hook
 * hard-block silently no-ops after a gateway restart.
 *
 * Enforcement is "enforced" only for a new external install — `origin` is not
 * bundled AND the install record was stamped (F.2 external-only + F.4
 * grandfather). Everything else is "grandfathered" (warn-mode). A malformed
 * manifest is logged and skipped (the plugin grandfathers) rather than failing
 * the whole load.
 *
 * @stable
 */
export function hydratePluginCapabilityGate(params: {
  pluginId: string;
  rootDir: string;
  origin: PluginOrigin;
  installRecord: PluginInstallRecord | undefined;
  logger?: { warn?: (message: string) => void };
}): void {
  const result = loadPluginCapabilitiesFromDir(params.rootDir);
  if (!result.ok) {
    params.logger?.warn?.(
      JSON.stringify({
        event: "plugin.capability.hydrate_failed",
        level: "warn",
        pluginId: params.pluginId,
        reason: result.reason,
      }),
    );
    return;
  }
  if (result.capabilities) {
    setPluginCapabilities(params.pluginId, result.capabilities);
  }
  const enforced =
    params.origin !== "bundled" && params.installRecord?.capabilityGate === "enforced";
  setPluginCapabilityEnforcement(params.pluginId, enforced ? "enforced" : "grandfathered");
}

// Owner: plugins/install. P1.7 install-time signature gate. Sits BETWEEN
// manifest validation and `scanAndLinkInstalledPackage` inside
// `installPluginFromPackageDir`. Refuses to write to disk when:
//   - no `openclaw.plugin.sig` sidecar is present and `--allow-unsigned` is off
//   - the sidecar signature does not verify against the canonical plugin hash
//   - the publisher is unknown to the workspace and is not first-party
//
// Returns a discriminated union mirroring `InstallPluginResult` so the caller
// can early-return without try/catch on the hot path. Security events MUST be
// surfaced; the named codes below are stable.

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { PluginPublisherPolicy } from "../config/types.plugins.js";
import {
  PLUGIN_SIGNATURE_SIDECAR_FILENAME,
  isPublisherTrusted,
  loadKnownPublishers,
  loadRevokedPublishers,
  parsePluginSignatureSidecar,
  verifyPluginSignature,
} from "../security/plugin-signing.js";
import { type PluginCapabilities } from "./capabilities.js";
import { loadPluginCapabilitiesFromDir } from "./plugin-capabilities-manifest.js";

export const PLUGIN_INSTALL_SIGNING_ERROR_CODE = {
  UNSIGNED: "plugin.install.unsigned",
  SIGNATURE_INVALID: "plugin.install.signature_invalid",
  UNKNOWN_PUBLISHER: "plugin.install.unknown_publisher",
  SIGNATURE_DRIFT: "plugin.install.signature_drift",
  CAPABILITIES_MALFORMED: "plugin.install.capabilities_malformed",
  PUBLISHER_REVOKED: "plugin.install.publisher_revoked",
  PUBLISHER_POLICY: "plugin.install.publisher_policy",
} as const;

export type PluginInstallSigningErrorCode =
  (typeof PLUGIN_INSTALL_SIGNING_ERROR_CODE)[keyof typeof PLUGIN_INSTALL_SIGNING_ERROR_CODE];

export type PluginSigningGateResult =
  | {
      ok: true;
      // Canonical source-tree hash (canonicalPluginHashHex). Present on the
      // signed path so the approval gate can pin to it without re-hashing;
      // absent on the allowUnsigned bypass (which returns before hashing).
      pluginHash?: string;
      publisherFingerprint?: string;
      // G.1 — capability manifest parsed from openclaw.plugin.json. Covered
      // by the same signed plugin_hash because openclaw.plugin.json lives in
      // the plugin source tree that gets hashed by `canonicalPluginHashHex`.
      // Absent capabilities block in the manifest is fine — runtime then
      // treats the plugin as fully constrained (deny-by-default) once the
      // host hook attachments / fetch wrappers consult the capabilities.
      capabilities?: PluginCapabilities;
    }
  | { ok: false; code: PluginInstallSigningErrorCode; reason: string };

export type PluginSigningGateOptions = {
  packageDir: string;
  pluginId: string;
  allowUnsigned?: boolean;
  knownPublishersPath?: string;
  revokedPublishersPath?: string;
  // Workspace publisher allow/deny policy + this plugin's per-entry
  // requirePublisher, evaluated after the publisher is otherwise trusted.
  publisherPolicy?: PluginPublisherPolicy;
  requirePublisher?: string[];
};

/**
 * Enforce the P1.7 signing policy on a staged plugin directory before any
 * files are linked into the workspace's `extensions/` tree.
 *
 * Failure modes: returns a non-ok variant for each named code; never throws on
 * expected refusal paths so the caller can format a structured user error.
 * Truly unexpected I/O errors (e.g. fs failure reading the sidecar) propagate.
 *
 * @stable
 */
export async function enforcePluginInstallSignature(
  opts: PluginSigningGateOptions,
): Promise<PluginSigningGateResult> {
  const sidecarPath = path.join(opts.packageDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME);
  if (!existsSync(sidecarPath)) {
    if (opts.allowUnsigned === true) {
      return { ok: true };
    }
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.UNSIGNED,
      reason: `plugin "${opts.pluginId}" has no ${PLUGIN_SIGNATURE_SIDECAR_FILENAME}; pass --allow-unsigned to bypass`,
    };
  }
  const raw = await readFile(sidecarPath, "utf8");
  const sidecar = parsePluginSignatureSidecar(raw);
  const { canonicalPluginHashHex } = await import("./plugins-lock.runtime.js");
  const pluginHash = await canonicalPluginHashHex(opts.packageDir);
  if (sidecar.plugin_hash !== pluginHash) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.SIGNATURE_DRIFT,
      reason: `plugin_hash in sidecar does not match the staged source tree`,
    };
  }
  const verifyResult = verifyPluginSignature(pluginHash, sidecar);
  if (!verifyResult.ok) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.SIGNATURE_INVALID,
      reason: verifyResult.reason,
    };
  }
  const fingerprint = sidecar.publisher.fingerprint;
  const revoked = loadRevokedPublishers(opts.revokedPublishersPath);
  if (revoked.includes(fingerprint)) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.PUBLISHER_REVOKED,
      reason: `publisher ${fingerprint} is revoked`,
    };
  }
  const known = loadKnownPublishers(opts.knownPublishersPath);
  if (!isPublisherTrusted(fingerprint, known, revoked)) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.UNKNOWN_PUBLISHER,
      reason: `publisher ${fingerprint} is not in known-publishers and is not first-party`,
    };
  }
  const policyVerdict = checkPublisherPolicy({
    fingerprint,
    policy: opts.publisherPolicy,
    requirePublisher: opts.requirePublisher,
  });
  if (!policyVerdict.ok) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.PUBLISHER_POLICY,
      reason: policyVerdict.reason,
    };
  }
  const capabilitiesResult = loadPluginCapabilitiesFromDir(opts.packageDir);
  if (!capabilitiesResult.ok) {
    return {
      ok: false,
      code: PLUGIN_INSTALL_SIGNING_ERROR_CODE.CAPABILITIES_MALFORMED,
      reason: capabilitiesResult.reason,
    };
  }
  return {
    ok: true,
    pluginHash,
    publisherFingerprint: sidecar.publisher.fingerprint,
    ...(capabilitiesResult.capabilities ? { capabilities: capabilitiesResult.capabilities } : {}),
  };
}

function checkPublisherPolicy(params: {
  fingerprint: string;
  policy?: PluginPublisherPolicy;
  requirePublisher?: string[];
}): { ok: true } | { ok: false; reason: string } {
  const { fingerprint, policy, requirePublisher } = params;
  if (policy?.denyPublisher?.includes(fingerprint)) {
    return {
      ok: false,
      reason: `publisher ${fingerprint} is denied by workspace publisher policy`,
    };
  }
  const required = [...(policy?.requirePublisher ?? []), ...(requirePublisher ?? [])];
  if (required.length > 0 && !required.includes(fingerprint)) {
    return {
      ok: false,
      reason: `publisher ${fingerprint} is not in the required-publisher allowlist`,
    };
  }
  return { ok: true };
}

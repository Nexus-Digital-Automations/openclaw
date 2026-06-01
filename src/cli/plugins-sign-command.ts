// Owner: cli/plugin-signing. Bridges the three publisher-side P1.7 commands
// (`openclaw plugins sign`, `openclaw plugins trust`, `openclaw plugins generate-key`)
// to the primitives in `src/security/plugin-signing.ts`. Hashes the plugin
// source tree via the same canonicalization plugins.lock uses, so signing and
// integrity locking commute by construction.
//
// State flow (publisher perspective):
//   generate-key -> sign -> distribute plugin + sidecar -> operator runs trust.
//
// Verification happens at install time inside `src/plugins/install.ts`, not here.

import { writeFile } from "node:fs/promises";
import path from "node:path";
import { defaultRuntime } from "../runtime.js";
import {
  PLUGIN_SIGNATURE_SIDECAR_FILENAME,
  addKnownPublisher,
  addRevokedPublisher,
  generateSigningKeypair,
  resolveKnownPublishersPath,
  resolveRevokedPublishersPath,
  signPluginHash,
  type PluginSignatureSidecar,
} from "../security/plugin-signing.js";

export type PluginsSignCommandOptions = {
  pluginDir: string;
  keyPath: string;
  json?: boolean;
};

export type PluginsTrustCommandOptions = {
  fingerprint: string;
  publicKeyHex: string;
  filePath?: string;
  json?: boolean;
};

export type PluginsGenerateKeyCommandOptions = {
  outDir: string;
  json?: boolean;
};

/**
 * Sign the plugin at `pluginDir` and write `openclaw.plugin.sig` next to its
 * `openclaw.plugin.json`. Re-runs are safe — the sidecar is overwritten.
 *
 * Failure modes: throws PluginSigningError if the key is missing or malformed,
 * propagates the underlying I/O error if hashing or writing the sidecar fails.
 *
 * @stable
 */
export async function runPluginsSignCommand(opts: PluginsSignCommandOptions): Promise<void> {
  const pluginRoot = path.resolve(opts.pluginDir);
  const keyPath = path.resolve(opts.keyPath);
  const { canonicalPluginHashHex } = await import("../plugins/plugins-lock.runtime.js");
  const pluginHash = await canonicalPluginHashHex(pluginRoot);
  const record = signPluginHash(pluginHash, keyPath);
  const sidecar: PluginSignatureSidecar = { ...record, plugin_hash: pluginHash };
  const sidecarPath = path.join(pluginRoot, PLUGIN_SIGNATURE_SIDECAR_FILENAME);
  await writeFile(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`, "utf8");
  if (opts.json) {
    defaultRuntime.writeJson({ ok: true, sidecarPath, publisher: record.publisher });
    return;
  }
  defaultRuntime.log(
    `Signed plugin at ${pluginRoot}\n  sidecar: ${sidecarPath}\n  fingerprint: ${record.publisher.fingerprint}`,
  );
}

/**
 * Add a publisher fingerprint to the workspace known-publishers registry.
 * Idempotent — re-adding the same fingerprint exits zero without rewriting.
 *
 * Failure modes: throws PluginSigningError on malformed fingerprint or hex.
 *
 * @stable
 */
export function runPluginsTrustCommand(opts: PluginsTrustCommandOptions): void {
  const filePath = opts.filePath ?? resolveKnownPublishersPath();
  addKnownPublisher(opts.fingerprint, opts.publicKeyHex, filePath);
  if (opts.json) {
    defaultRuntime.writeJson({ ok: true, fingerprint: opts.fingerprint, filePath });
    return;
  }
  defaultRuntime.log(`Trusted publisher ${opts.fingerprint}\n  registry: ${filePath}`);
}

/**
 * Generate an Ed25519 keypair and persist it to `outDir`. Prints the
 * fingerprint so publishers can immediately request operators trust them.
 *
 * Failure modes: filesystem errors propagate from `generateSigningKeypair`.
 *
 * @stable
 */
export function runPluginsGenerateKeyCommand(opts: PluginsGenerateKeyCommandOptions): void {
  const outDir = path.resolve(opts.outDir);
  const result = generateSigningKeypair(outDir);
  if (opts.json) {
    defaultRuntime.writeJson({
      ok: true,
      privateKeyPath: result.privateKeyPath,
      publicKeyPath: result.publicKeyPath,
      publisher: result.publisher,
    });
    return;
  }
  defaultRuntime.log(
    `Generated Ed25519 keypair\n  private: ${result.privateKeyPath}\n  public:  ${result.publicKeyPath}\n  fingerprint: ${result.publisher.fingerprint}\n  publicKeyHex: ${result.publisher.publicKeyHex}`,
  );
}

export type PluginsRevokeCommandOptions = {
  fingerprint: string;
  filePath?: string;
  json?: boolean;
};

/**
 * Revoke a publisher fingerprint in the workspace revoked-publishers registry.
 * A revoked fingerprint is refused at install even if it is first-party or in
 * known-publishers. Idempotent.
 *
 * Failure modes: throws PluginSigningError on malformed fingerprint.
 *
 * @stable
 */
export function runPluginsRevokeCommand(opts: PluginsRevokeCommandOptions): void {
  const filePath = opts.filePath ?? resolveRevokedPublishersPath();
  addRevokedPublisher(opts.fingerprint, filePath);
  if (opts.json) {
    defaultRuntime.writeJson({ ok: true, fingerprint: opts.fingerprint, filePath });
    return;
  }
  defaultRuntime.log(`Revoked publisher ${opts.fingerprint}\n  registry: ${filePath}`);
}

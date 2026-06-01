#!/usr/bin/env node
// Owner: scripts/sign-bundled-plugins. Maintainer/release tool. Signs the
// built bundled-plugin trees with the first-party Ed25519 private key, writing
// an `openclaw.plugin.sig` sidecar next to each plugin's `openclaw.plugin.json`
// that the install-signing gate verifies.
//
// Parity guarantee: imports the SAME TS the install gate hashes with
// (canonicalPluginHashHex + signPluginHash) via jiti, and hashes each plugin
// directory IN PLACE — so the signed bytes equal the bytes the gate later
// hashes for that exact tree. No reimplementation that could drift.
//
// Dormant by default: enforcement (OPENCLAW_REQUIRE_SIGNED_PLUGINS) stays off,
// so unsigned bundled plugins still install today. This is forward-prep so a
// future enforcement flip finds valid first-party signatures already in place.
//
// Usage (release time, with the offline-held first-party key):
//   node scripts/sign-bundled-plugins.mjs --key <path-to-private.pem> [--dir <root>]
//   OPENCLAW_PLUGIN_SIGNING_KEY=<path> node scripts/sign-bundled-plugins.mjs
// With NO key, the script logs once and exits 0 without writing anything, so it
// is safe to call from a keyless dev/CI build. Never commit a private key.

import { existsSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createJiti } from "jiti";

function parseArgs(argv) {
  const keyFlagIndex = argv.indexOf("--key");
  const keyFromFlag = keyFlagIndex === -1 ? undefined : argv[keyFlagIndex + 1];
  const dirFlagIndex = argv.indexOf("--dir");
  const dirFromFlag = dirFlagIndex === -1 ? undefined : argv[dirFlagIndex + 1];
  const keyPath = keyFromFlag ?? process.env.OPENCLAW_PLUGIN_SIGNING_KEY?.trim();
  return { keyPath: keyPath || undefined, dirFromFlag };
}

async function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const { keyPath, dirFromFlag } = parseArgs(process.argv.slice(2));

  if (!keyPath) {
    process.stdout.write(
      "sign-bundled-plugins: no signing key (--key / OPENCLAW_PLUGIN_SIGNING_KEY); leaving bundled plugins unsigned (dormant)\n",
    );
    return;
  }

  const extensionsRoot = dirFromFlag
    ? path.resolve(dirFromFlag)
    : path.join(repoRoot, "dist", "extensions");
  if (!existsSync(extensionsRoot)) {
    throw new Error(`bundled-extensions root not found: ${extensionsRoot} (build dist first)`);
  }

  const jiti = createJiti(import.meta.url);
  const { canonicalPluginHashHex } = await jiti.import(
    path.join(repoRoot, "src/plugins/plugins-lock.runtime.ts"),
  );
  const { signPluginHash, PLUGIN_SIGNATURE_SIDECAR_FILENAME } = await jiti.import(
    path.join(repoRoot, "src/security/plugin-signing.ts"),
  );

  let signed = 0;
  for (const dirent of readdirSync(extensionsRoot, { withFileTypes: true })) {
    if (!dirent.isDirectory()) {
      continue;
    }
    const pluginDir = path.join(extensionsRoot, dirent.name);
    if (!existsSync(path.join(pluginDir, "openclaw.plugin.json"))) {
      continue;
    }
    const pluginHash = await canonicalPluginHashHex(pluginDir);
    const record = signPluginHash(pluginHash, keyPath);
    const sidecar = { ...record, plugin_hash: pluginHash };
    const sidecarPath = path.join(pluginDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME);
    writeFileSync(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`, "utf8");
    signed += 1;
    process.stdout.write(`  signed ${dirent.name} -> ${sidecarPath}\n`);
  }
  process.stdout.write(
    `sign-bundled-plugins: signed ${signed} bundled plugin(s) in ${extensionsRoot}\n`,
  );
}

await main();

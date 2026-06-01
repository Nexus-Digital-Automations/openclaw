#!/usr/bin/env node
// Owner: scripts/sign-official-catalog. Maintainer release tool. Signs the
// official external catalog with the first-party Ed25519 private key and writes
// the committed signature artifact (scripts/lib/official-external-catalog-signature.json)
// that the runtime verifies in `official-external-plugin-catalog.ts`.
//
// Parity guarantee: imports the SAME TS source the loader verifies with
// (canonicalCatalogHashHex + officialCatalogSignaturePayload + signPluginHash)
// via jiti, so the signed bytes and the verified bytes are identical — there is
// no separate hash reimplementation that could drift.
//
// Usage (release time, with the offline-held first-party key):
//   node scripts/sign-official-catalog.mjs --key <path-to-private.pem>
// Then commit the updated signature JSON. Runtime refuses a catalog whose
// signature no longer matches (tampered trust anchor).

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createJiti } from "jiti";

function parseKeyPath(argv) {
  const idx = argv.indexOf("--key");
  const value = idx === -1 ? undefined : argv[idx + 1];
  if (!value) {
    throw new Error("usage: node scripts/sign-official-catalog.mjs --key <private.pem>");
  }
  return path.resolve(value);
}

async function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const keyPath = parseKeyPath(process.argv.slice(2));
  const jiti = createJiti(import.meta.url);
  const { canonicalCatalogHashHex } = await jiti.import(
    path.join(repoRoot, "src/plugins/official-catalog-signature.ts"),
  );
  const { officialCatalogSignaturePayload } = await jiti.import(
    path.join(repoRoot, "src/plugins/official-external-plugin-catalog.ts"),
  );
  const { signPluginHash } = await jiti.import(
    path.join(repoRoot, "src/security/plugin-signing.ts"),
  );

  const pluginHash = canonicalCatalogHashHex(officialCatalogSignaturePayload());
  const record = signPluginHash(pluginHash, keyPath);
  const sidecar = { ...record, plugin_hash: pluginHash };
  const outPath = path.join(repoRoot, "scripts/lib/official-external-catalog-signature.json");
  writeFileSync(outPath, `${JSON.stringify({ version: 1, sidecar }, null, 2)}\n`, "utf8");
  process.stdout.write(
    `Signed official catalog -> ${outPath}\n  publisher: ${sidecar.publisher.fingerprint}\n`,
  );
}

await main();

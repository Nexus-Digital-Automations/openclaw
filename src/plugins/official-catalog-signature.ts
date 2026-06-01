// Owner: plugins/official-catalog. Ed25519 signing + verification for the
// official external plugin/channel/provider catalog. The catalog is a trust
// anchor (it tells the installer which npm/clawhub specs are "official"), so a
// tampered catalog could redirect installs. This signs the canonical catalog
// bytes with the first-party key at build and verifies at load.
//
// Canonicalization sorts object keys recursively so the signed bytes are
// stable regardless of serialization order (mirrors the deterministic-ordering
// rule for prompt-cache inputs).

import crypto from "node:crypto";
import {
  FIRST_PARTY_PUBLISHER_FINGERPRINT,
  type PluginSignatureSidecar,
  verifyPluginSignature,
} from "../security/plugin-signing.js";

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .toSorted()
        .map((key) => [key, canonicalize(record[key])]),
    );
  }
  return value;
}

/**
 * Stable sha256 hex of the catalog's canonical (sorted-key) JSON form. The same
 * bytes are hashed at signing time and verify time.
 *
 * @stable
 */
export function canonicalCatalogHashHex(catalog: unknown): string {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(canonicalize(catalog)), "utf8")
    .digest("hex");
}

export type CatalogSignatureVerdict = { ok: true } | { ok: false; reason: string };

/**
 * Verify a catalog signature sidecar against the catalog object. Refuses when
 * the hash drifts, the signer is not the expected first-party publisher, or the
 * Ed25519 signature does not verify. `expectedFingerprint` defaults to the
 * build-injected first-party fingerprint; it is a parameter so tests can sign
 * with their own key.
 *
 * @stable
 */
export function verifyOfficialCatalogSignature(
  catalog: unknown,
  sidecar: PluginSignatureSidecar,
  expectedFingerprint: string = FIRST_PARTY_PUBLISHER_FINGERPRINT,
): CatalogSignatureVerdict {
  const hash = canonicalCatalogHashHex(catalog);
  if (sidecar.plugin_hash !== hash) {
    return { ok: false, reason: "catalog hash does not match its signature (tampered or stale)" };
  }
  if (sidecar.publisher.fingerprint !== expectedFingerprint) {
    return { ok: false, reason: "catalog signed by a non-first-party publisher" };
  }
  const verify = verifyPluginSignature(hash, sidecar);
  if (!verify.ok) {
    return { ok: false, reason: verify.reason };
  }
  return { ok: true };
}

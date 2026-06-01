// Owner: security/plugin-signing. P1.7 of the OpenClaw security roadmap.
// Provides Ed25519 detached-signature primitives that gate plugin installs.
//
// State machine for a signing keypair lifecycle:
//   1. generate-key  -> two PEM files on disk (private PKCS8 + public SPKI)
//   2. sign          -> signature over the P0.5 canonical plugin hash, written
//                       to `openclaw.plugin.sig` alongside `openclaw.plugin.json`
//   3. trust         -> operator adds the publisher fingerprint to the workspace
//                       known-publishers registry (`~/.openclaw/known-publishers.json`)
//   4. verify        -> install gate recomputes the plugin hash, verifies the
//                       signature, and only proceeds if the publisher matches a
//                       trusted entry (or the hardcoded first-party fingerprint).
//
// Sigstore-style transparency lands in P3.3; the first-party fingerprint constant
// below is the offline-rooted stopgap until then.
//
// All functions throw structured errors on failure. The install-time gate maps
// those to the named codes documented in `install.ts`.

import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { resolveRequiredHomeDir } from "../infra/home-dir.js";

// First-party (OpenClaw maintainer) publisher fingerprint, injected at build
// via OPENCLAW_FIRST_PARTY_FINGERPRINT (release builds set it; mirrors the
// OPENCLAW_BUNDLED_VERSION pattern in version.ts). Source / unconfigured builds
// fall back to the all-zeros placeholder, which matches no real Ed25519
// fingerprint — so they trust only explicitly `plugins trust`-ed publishers,
// never an accidental key. TODO: P3.3 sigstore transparency log supersedes this.
const FIRST_PARTY_FINGERPRINT_PLACEHOLDER =
  "0000000000000000000000000000000000000000000000000000000000000000".slice(0, 32);
export const FIRST_PARTY_PUBLISHER_FINGERPRINT =
  process.env.OPENCLAW_FIRST_PARTY_FINGERPRINT?.trim() || FIRST_PARTY_FINGERPRINT_PLACEHOLDER;

const FINGERPRINT_HEX_LENGTH = 32;

export type PublisherIdentity = {
  /** sha256(publicKey raw bytes) hex, truncated to 32 chars. */
  fingerprint: string;
  /** Full hex of the SPKI raw public key bytes. */
  publicKeyHex: string;
};

export type SignatureRecord = {
  signature: string; // base64
  publisher: PublisherIdentity;
  signedAt: string; // ISO-8601 UTC
};

export type SignPluginHashResult = SignatureRecord;

export class PluginSigningError extends Error {
  readonly code: string;
  constructor(code: string, message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "PluginSigningError";
    this.code = code;
  }
}

/**
 * Compute the canonical fingerprint hex from a public key's raw SPKI bytes.
 * Stable across runs as long as the same key is supplied.
 *
 * @stable
 */
export function fingerprintForPublicKey(publicKeyRaw: Buffer): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyRaw)
    .digest("hex")
    .slice(0, FINGERPRINT_HEX_LENGTH);
}

function readPemKey(
  absPath: string,
  expectedHeader: "PRIVATE KEY" | "PUBLIC KEY",
): crypto.KeyObject {
  let pem: string;
  try {
    pem = readFileSync(absPath, "utf8");
  } catch (err) {
    throw new PluginSigningError(
      "plugin.signing.key_missing",
      `cannot read key at ${absPath}`,
      err,
    );
  }
  if (!pem.includes(`-----BEGIN ${expectedHeader}-----`)) {
    throw new PluginSigningError(
      "plugin.signing.key_format_invalid",
      `expected ${expectedHeader} PEM at ${absPath}`,
    );
  }
  if (expectedHeader === "PRIVATE KEY") {
    return crypto.createPrivateKey({ key: pem, format: "pem" });
  }
  return crypto.createPublicKey({ key: pem, format: "pem" });
}

function exportPublicSpkiBytes(publicKey: crypto.KeyObject): Buffer {
  return publicKey.export({ format: "der", type: "spki" }) as Buffer;
}

/**
 * Sign the canonical plugin hash with the Ed25519 private key at `privateKeyPath`.
 *
 * Failure modes: throws PluginSigningError when the key is missing, malformed,
 * or the wrong algorithm (Ed25519 only). The signature covers the literal hash
 * bytes — callers MUST pass the exact hex string `plugins-lock.ts` would record.
 *
 * @stable
 */
export function signPluginHash(pluginHash: string, privateKeyPath: string): SignPluginHashResult {
  if (!/^[a-f0-9]{64}$/u.test(pluginHash)) {
    throw new PluginSigningError("plugin.signing.hash_invalid", "plugin hash must be sha256 hex");
  }
  const privateKey = readPemKey(privateKeyPath, "PRIVATE KEY");
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new PluginSigningError("plugin.signing.key_algorithm", "private key must be Ed25519");
  }
  const publicKey = crypto.createPublicKey(privateKey);
  const publicKeyRaw = exportPublicSpkiBytes(publicKey);
  const signature = crypto.sign(null, Buffer.from(pluginHash, "utf8"), privateKey);
  return {
    signature: signature.toString("base64"),
    publisher: {
      fingerprint: fingerprintForPublicKey(publicKeyRaw),
      publicKeyHex: publicKeyRaw.toString("hex"),
    },
    signedAt: new Date().toISOString(),
  };
}

/**
 * Verify that `signatureRecord` is a valid Ed25519 signature over `pluginHash`
 * issued by the publisher embedded in the record. Returns a discriminated
 * union so callers can branch without a try/catch on the hot path.
 *
 * @stable
 */
export function verifyPluginSignature(
  pluginHash: string,
  signatureRecord: SignatureRecord,
): { ok: true } | { ok: false; reason: string } {
  if (!/^[a-f0-9]{64}$/u.test(pluginHash)) {
    return { ok: false, reason: "plugin hash must be sha256 hex" };
  }
  let publicKeyRaw: Buffer;
  try {
    publicKeyRaw = Buffer.from(signatureRecord.publisher.publicKeyHex, "hex");
  } catch {
    return { ok: false, reason: "publisher publicKeyHex is not hex" };
  }
  const expectedFingerprint = fingerprintForPublicKey(publicKeyRaw);
  if (expectedFingerprint !== signatureRecord.publisher.fingerprint) {
    return { ok: false, reason: "publisher fingerprint does not match embedded public key" };
  }
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({
      key: publicKeyRaw,
      format: "der",
      type: "spki",
    });
  } catch (err) {
    return { ok: false, reason: `cannot import public key: ${(err as Error).message}` };
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    return { ok: false, reason: "public key is not Ed25519" };
  }
  const verified = crypto.verify(
    null,
    Buffer.from(pluginHash, "utf8"),
    publicKey,
    Buffer.from(signatureRecord.signature, "base64"),
  );
  if (!verified) {
    return { ok: false, reason: "signature does not verify against plugin hash" };
  }
  return { ok: true };
}

/**
 * Resolve the default known-publishers registry path under the resolved home dir.
 *
 * @stable
 */
export function resolveKnownPublishersPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(resolveRequiredHomeDir(env), ".openclaw", "known-publishers.json");
}

type KnownPublishersFile = {
  version: 1;
  publishers: PublisherIdentity[];
};

function emptyKnownPublishers(): KnownPublishersFile {
  return { version: 1, publishers: [] };
}

/**
 * Load the operator-managed list of trusted publisher identities. Returns an
 * empty list if the file is absent; throws on malformed JSON so silent trust
 * regressions are impossible.
 *
 * @stable
 */
export function loadKnownPublishers(filePath?: string): PublisherIdentity[] {
  const target = filePath ?? resolveKnownPublishersPath();
  if (!existsSync(target)) {
    return [];
  }
  const raw = readFileSync(target, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isKnownPublishersFile(parsed)) {
    throw new PluginSigningError(
      "plugin.signing.known_publishers_invalid",
      `known-publishers.json at ${target} is malformed`,
    );
  }
  return [...parsed.publishers];
}

function isKnownPublishersFile(value: unknown): value is KnownPublishersFile {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as { version?: unknown; publishers?: unknown };
  if (candidate.version !== 1 || !Array.isArray(candidate.publishers)) {
    return false;
  }
  return candidate.publishers.every(
    (entry) =>
      entry &&
      typeof entry === "object" &&
      typeof (entry as PublisherIdentity).fingerprint === "string" &&
      typeof (entry as PublisherIdentity).publicKeyHex === "string",
  );
}

/**
 * Append a publisher identity to the known-publishers registry. Idempotent:
 * re-adding the same fingerprint is a no-op rather than an error so onboarding
 * scripts stay safe to rerun.
 *
 * @stable
 */
export function addKnownPublisher(
  fingerprint: string,
  publicKeyHex: string,
  filePath?: string,
): void {
  if (fingerprint.length !== FINGERPRINT_HEX_LENGTH || !/^[a-f0-9]+$/u.test(fingerprint)) {
    throw new PluginSigningError(
      "plugin.signing.fingerprint_invalid",
      `fingerprint must be ${FINGERPRINT_HEX_LENGTH} lowercase hex chars`,
    );
  }
  if (!/^[a-f0-9]+$/u.test(publicKeyHex) || publicKeyHex.length === 0) {
    throw new PluginSigningError("plugin.signing.public_key_invalid", "publicKeyHex must be hex");
  }
  const target = filePath ?? resolveKnownPublishersPath();
  const current = existsSync(target) ? loadKnownPublishersAsFile(target) : emptyKnownPublishers();
  if (current.publishers.some((entry) => entry.fingerprint === fingerprint)) {
    return;
  }
  current.publishers.push({ fingerprint, publicKeyHex });
  current.publishers.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(current, null, 2)}\n`, "utf8");
}

function loadKnownPublishersAsFile(filePath: string): KnownPublishersFile {
  const raw = readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isKnownPublishersFile(parsed)) {
    throw new PluginSigningError(
      "plugin.signing.known_publishers_invalid",
      `known-publishers.json at ${filePath} is malformed`,
    );
  }
  return { version: 1, publishers: [...parsed.publishers] };
}

/**
 * Resolve the default revoked-publishers registry path under the resolved home.
 *
 * @stable
 */
export function resolveRevokedPublishersPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(resolveRequiredHomeDir(env), ".openclaw", "revoked-publishers.json");
}

type RevokedPublishersFile = {
  version: 1;
  revoked: string[];
};

function isRevokedPublishersFile(value: unknown): value is RevokedPublishersFile {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as { version?: unknown; revoked?: unknown };
  if (candidate.version !== 1 || !Array.isArray(candidate.revoked)) {
    return false;
  }
  return candidate.revoked.every((entry) => typeof entry === "string");
}

/**
 * Load the operator-managed list of revoked publisher fingerprints. Empty when
 * absent; throws on malformed JSON so a corrupted file never silently
 * re-trusts a revoked key.
 *
 * @stable
 */
export function loadRevokedPublishers(filePath?: string): string[] {
  const target = filePath ?? resolveRevokedPublishersPath();
  if (!existsSync(target)) {
    return [];
  }
  const raw = readFileSync(target, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isRevokedPublishersFile(parsed)) {
    throw new PluginSigningError(
      "plugin.signing.revoked_publishers_invalid",
      `revoked-publishers.json at ${target} is malformed`,
    );
  }
  return [...parsed.revoked];
}

/**
 * Revoke a publisher fingerprint. Idempotent. A revoked fingerprint is refused
 * by `isPublisherTrusted` even if it is also first-party or known-trusted.
 *
 * @stable
 */
export function addRevokedPublisher(fingerprint: string, filePath?: string): void {
  if (fingerprint.length !== FINGERPRINT_HEX_LENGTH || !/^[a-f0-9]+$/u.test(fingerprint)) {
    throw new PluginSigningError(
      "plugin.signing.fingerprint_invalid",
      `fingerprint must be ${FINGERPRINT_HEX_LENGTH} lowercase hex chars`,
    );
  }
  const target = filePath ?? resolveRevokedPublishersPath();
  const revoked = existsSync(target) ? loadRevokedPublishers(target) : [];
  if (revoked.includes(fingerprint)) {
    return;
  }
  const next: RevokedPublishersFile = {
    version: 1,
    revoked: [...revoked, fingerprint].toSorted((a, b) => a.localeCompare(b)),
  };
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(next, null, 2)}\n`, "utf8");
}

/**
 * Check whether a publisher is trusted. Revoke-first: a revoked fingerprint is
 * never trusted, even if it is first-party or in the known-publishers registry.
 * Otherwise trusted when it matches the first-party fingerprint or a workspace
 * known-publishers entry.
 *
 * @stable
 */
export function isPublisherTrusted(
  fingerprint: string,
  knownPublishers: readonly PublisherIdentity[],
  revokedFingerprints: readonly string[] = [],
): boolean {
  if (revokedFingerprints.includes(fingerprint)) {
    return false;
  }
  if (fingerprint === FIRST_PARTY_PUBLISHER_FINGERPRINT) {
    return true;
  }
  return knownPublishers.some((entry) => entry.fingerprint === fingerprint);
}

/**
 * Generate a fresh Ed25519 keypair and persist it as `<outDir>/private.pem`
 * plus `<outDir>/public.pem`. Returns the publisher identity so callers can
 * display the fingerprint immediately.
 *
 * @stable
 */
export function generateSigningKeypair(outDir: string): {
  privateKeyPath: string;
  publicKeyPath: string;
  publisher: PublisherIdentity;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ format: "pem", type: "pkcs8" });
  const publicPem = publicKey.export({ format: "pem", type: "spki" });
  mkdirSync(outDir, { recursive: true });
  const privateKeyPath = path.join(outDir, "private.pem");
  const publicKeyPath = path.join(outDir, "public.pem");
  writeFileSync(privateKeyPath, privatePem, { mode: 0o600 });
  writeFileSync(publicKeyPath, publicPem);
  const publicKeyRaw = exportPublicSpkiBytes(publicKey);
  return {
    privateKeyPath,
    publicKeyPath,
    publisher: {
      fingerprint: fingerprintForPublicKey(publicKeyRaw),
      publicKeyHex: publicKeyRaw.toString("hex"),
    },
  };
}

export const PLUGIN_SIGNATURE_SIDECAR_FILENAME = "openclaw.plugin.sig";

export type PluginSignatureSidecar = SignatureRecord & {
  /** The exact canonical hash that `plugins-lock` computes for the source tree. */
  plugin_hash: string;
};

/**
 * Parse the contents of an `openclaw.plugin.sig` sidecar file. Throws on shape
 * drift so an unknown sidecar version never silently passes verification.
 *
 * @stable
 */
export function parsePluginSignatureSidecar(json: string): PluginSignatureSidecar {
  const parsed = JSON.parse(json) as unknown;
  if (!isPluginSignatureSidecar(parsed)) {
    throw new PluginSigningError(
      "plugin.signing.sidecar_invalid",
      "openclaw.plugin.sig is missing required fields",
    );
  }
  return parsed;
}

function isPluginSignatureSidecar(value: unknown): value is PluginSignatureSidecar {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.signature !== "string" ||
    typeof candidate.signedAt !== "string" ||
    typeof candidate.plugin_hash !== "string"
  ) {
    return false;
  }
  const publisher = candidate.publisher as Record<string, unknown> | undefined;
  if (
    !publisher ||
    typeof publisher.fingerprint !== "string" ||
    typeof publisher.publicKeyHex !== "string"
  ) {
    return false;
  }
  return true;
}

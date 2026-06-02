// Owner: security/plugin-signing. Critical-path tests for the P1.7 signing
// primitives. Each spec describes a tampering scenario the install gate MUST
// refuse; silent regressions here are a security incident.

import crypto from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  addKnownPublisher,
  addRevokedPublisher,
  fingerprintForPublicKey,
  generateSigningKeypair,
  isPublisherTrusted,
  loadKnownPublishers,
  loadRevokedPublishers,
  PluginSigningError,
  resolveKnownPublishersPath,
  signPluginHash,
  verifyPluginSignature,
  FIRST_PARTY_FINGERPRINT_PLACEHOLDER,
  FIRST_PARTY_PUBLISHER_FINGERPRINT,
  isFirstPartyFingerprintShape,
} from "./plugin-signing.js";

let workspaceDir = "";

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-plugin-signing-"));
});

afterEach(async () => {
  await rm(workspaceDir, { force: true, recursive: true });
});

function freshHash(): string {
  return crypto.createHash("sha256").update(crypto.randomBytes(32)).digest("hex");
}

describe("isPublisherTrusted — revocation precedence", () => {
  it("refuses a revoked fingerprint even when it is first-party", () => {
    expect(
      isPublisherTrusted(
        FIRST_PARTY_PUBLISHER_FINGERPRINT,
        [],
        [FIRST_PARTY_PUBLISHER_FINGERPRINT],
      ),
    ).toBe(false);
  });

  it("refuses a revoked fingerprint even when it is in known-publishers", () => {
    const known = [{ fingerprint: "a".repeat(32), publicKeyHex: "ab" }];
    expect(isPublisherTrusted("a".repeat(32), known, ["a".repeat(32)])).toBe(false);
  });

  it("still trusts a known publisher that is not revoked", () => {
    const known = [{ fingerprint: "a".repeat(32), publicKeyHex: "ab" }];
    expect(isPublisherTrusted("a".repeat(32), known, ["b".repeat(32)])).toBe(true);
  });

  it("round-trips addRevokedPublisher -> loadRevokedPublishers and is idempotent", () => {
    const filePath = path.join(workspaceDir, "revoked-publishers.json");
    addRevokedPublisher("c".repeat(32), filePath);
    addRevokedPublisher("c".repeat(32), filePath);
    expect(loadRevokedPublishers(filePath)).toEqual(["c".repeat(32)]);
  });
});

describe("sign + verify roundtrip", () => {
  it("verifies a signature produced by the matching private key", async () => {
    const kp = generateSigningKeypair(workspaceDir);
    const pluginHash = freshHash();
    const record = signPluginHash(pluginHash, kp.privateKeyPath);
    const result = verifyPluginSignature(pluginHash, record);
    expect(result.ok).toBe(true);
    expect(record.publisher.fingerprint).toBe(kp.publisher.fingerprint);
  });

  it("rejects when the signed hash was tampered with", async () => {
    const kp = generateSigningKeypair(workspaceDir);
    const original = freshHash();
    const record = signPluginHash(original, kp.privateKeyPath);
    const tampered = freshHash();
    const result = verifyPluginSignature(tampered, record);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("signature does not verify");
    }
  });

  it("rejects when the signature bytes were swapped", async () => {
    const kp = generateSigningKeypair(workspaceDir);
    const pluginHash = freshHash();
    const record = signPluginHash(pluginHash, kp.privateKeyPath);
    const tamperedSignature = Buffer.from(record.signature, "base64");
    tamperedSignature[0] ^= 0x01;
    const result = verifyPluginSignature(pluginHash, {
      ...record,
      signature: tamperedSignature.toString("base64"),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects when the embedded public key does not match the signing key", async () => {
    const signer = generateSigningKeypair(path.join(workspaceDir, "signer"));
    const impostor = generateSigningKeypair(path.join(workspaceDir, "impostor"));
    const pluginHash = freshHash();
    const record = signPluginHash(pluginHash, signer.privateKeyPath);
    const result = verifyPluginSignature(pluginHash, {
      ...record,
      publisher: impostor.publisher,
    });
    expect(result.ok).toBe(false);
  });
});

describe("fingerprint canonicalization", () => {
  it("returns the same fingerprint for the same public key bytes across runs", () => {
    const kp = generateSigningKeypair(workspaceDir);
    const publicPem = readFileSync(kp.publicKeyPath, "utf8");
    const publicKey = crypto.createPublicKey({ key: publicPem, format: "pem" });
    const raw = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    expect(fingerprintForPublicKey(raw)).toBe(kp.publisher.fingerprint);
    expect(fingerprintForPublicKey(raw)).toBe(fingerprintForPublicKey(raw));
    expect(kp.publisher.fingerprint).toMatch(/^[a-f0-9]{32}$/u);
  });
});

describe("sign-time validation", () => {
  it("refuses a hash that is not sha256 hex", () => {
    const kp = generateSigningKeypair(workspaceDir);
    expect(() => signPluginHash("not-a-hash", kp.privateKeyPath)).toThrow(PluginSigningError);
  });

  it("refuses an RSA private key", async () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPath = path.join(workspaceDir, "rsa-private.pem");
    await writeFile(rsaPath, privateKey.export({ format: "pem", type: "pkcs8" }));
    expect(() => signPluginHash(freshHash(), rsaPath)).toThrow(PluginSigningError);
  });
});

describe("known-publishers registry", () => {
  it("appends a publisher and survives a read-back", () => {
    const kp = generateSigningKeypair(workspaceDir);
    const registryPath = path.join(workspaceDir, "known-publishers.json");
    addKnownPublisher(kp.publisher.fingerprint, kp.publisher.publicKeyHex, registryPath);
    const loaded = loadKnownPublishers(registryPath);
    expect(loaded).toHaveLength(1);
    expect(loaded[0]?.fingerprint).toBe(kp.publisher.fingerprint);
  });

  it("is idempotent for the same fingerprint", () => {
    const kp = generateSigningKeypair(workspaceDir);
    const registryPath = path.join(workspaceDir, "known-publishers.json");
    addKnownPublisher(kp.publisher.fingerprint, kp.publisher.publicKeyHex, registryPath);
    addKnownPublisher(kp.publisher.fingerprint, kp.publisher.publicKeyHex, registryPath);
    expect(loadKnownPublishers(registryPath)).toHaveLength(1);
  });

  it("marks an unknown publisher as untrusted", () => {
    const kp = generateSigningKeypair(workspaceDir);
    expect(isPublisherTrusted(kp.publisher.fingerprint, [])).toBe(false);
  });

  it("trusts the first-party fingerprint without a registry entry", () => {
    expect(isPublisherTrusted(FIRST_PARTY_PUBLISHER_FINGERPRINT, [])).toBe(true);
  });

  it("rejects a malformed fingerprint on add", () => {
    expect(() => addKnownPublisher("zzz", "deadbeef", path.join(workspaceDir, "kp.json"))).toThrow(
      PluginSigningError,
    );
  });
});

describe("resolveKnownPublishersPath", () => {
  it("anchors the registry under the resolved home dir", () => {
    const result = resolveKnownPublishersPath({ HOME: workspaceDir });
    expect(result.startsWith(workspaceDir)).toBe(true);
    expect(result.endsWith(path.join(".openclaw", "known-publishers.json"))).toBe(true);
  });
});

describe("private key file mode", () => {
  it("writes the private PEM with 0o600 permissions", () => {
    if (process.platform === "win32") {
      // Windows POSIX perms don't map; skip without false-positive.
      return;
    }
    const kp = generateSigningKeypair(workspaceDir);
    const stat = statSync(kp.privateKeyPath);
    // mode bits low 9 bits = perms; 0o600 = owner read/write only.
    expect(stat.mode & 0o777).toBe(0o600);
  });
});

describe("first-party fingerprint trust root", () => {
  it("stays dormant (all-zeros placeholder) in an unconfigured build", () => {
    // No build-info.json stamp and no OPENCLAW_FIRST_PARTY_FINGERPRINT in the
    // test env, so the resolved trust root must be the sentinel that matches no
    // real key — never an accidental fingerprint.
    expect(FIRST_PARTY_PUBLISHER_FINGERPRINT).toBe(FIRST_PARTY_FINGERPRINT_PLACEHOLDER);
    expect(FIRST_PARTY_FINGERPRINT_PLACEHOLDER).toBe("0".repeat(32));
  });

  it("accepts a canonical 32-lowercase-hex fingerprint", () => {
    const kp = generateSigningKeypair(workspaceDir);
    expect(isFirstPartyFingerprintShape(kp.publisher.fingerprint)).toBe(true);
    expect(isFirstPartyFingerprintShape(FIRST_PARTY_FINGERPRINT_PLACEHOLDER)).toBe(true);
  });

  it("rejects malformed fingerprints (wrong length, uppercase, undefined)", () => {
    expect(isFirstPartyFingerprintShape("abc")).toBe(false);
    expect(isFirstPartyFingerprintShape("A".repeat(32))).toBe(false);
    expect(isFirstPartyFingerprintShape("g".repeat(32))).toBe(false);
    expect(isFirstPartyFingerprintShape(undefined)).toBe(false);
  });
});

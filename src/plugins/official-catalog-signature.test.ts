/**
 * Owner: plugins/official-catalog-signature.test
 *
 * Spec: the official catalog is a trust anchor; a tampered or non-first-party
 * signature MUST be refused so installs cannot be redirected to attacker specs.
 */
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  generateSigningKeypair,
  type PluginSignatureSidecar,
  signPluginHash,
} from "../security/plugin-signing.js";
import {
  canonicalCatalogHashHex,
  verifyOfficialCatalogSignature,
} from "./official-catalog-signature.js";

let workspaceDir = "";

const catalog = { entries: [{ name: "@openclaw/acpx", openclaw: { plugin: { id: "acpx" } } }] };

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-catalog-sig-"));
});

afterEach(async () => {
  await rm(workspaceDir, { force: true, recursive: true });
});

function signCatalog(obj: unknown): { sidecar: PluginSignatureSidecar; fingerprint: string } {
  const kp = generateSigningKeypair(workspaceDir);
  const hash = canonicalCatalogHashHex(obj);
  const record = signPluginHash(hash, kp.privateKeyPath);
  return { sidecar: { ...record, plugin_hash: hash }, fingerprint: kp.publisher.fingerprint };
}

describe("verifyOfficialCatalogSignature", () => {
  it("accepts a catalog signed by the expected first-party key", () => {
    const { sidecar, fingerprint } = signCatalog(catalog);
    expect(verifyOfficialCatalogSignature(catalog, sidecar, fingerprint)).toEqual({ ok: true });
  });

  it("is stable across key reordering (canonical hash)", () => {
    const { sidecar, fingerprint } = signCatalog(catalog);
    const reordered = {
      entries: [{ openclaw: { plugin: { id: "acpx" } }, name: "@openclaw/acpx" }],
    };
    expect(verifyOfficialCatalogSignature(reordered, sidecar, fingerprint)).toEqual({ ok: true });
  });

  it("refuses a tampered catalog (hash drift)", () => {
    const { sidecar, fingerprint } = signCatalog(catalog);
    const tampered = { entries: [{ name: "@evil/pkg", openclaw: { plugin: { id: "acpx" } } }] };
    const verdict = verifyOfficialCatalogSignature(tampered, sidecar, fingerprint);
    expect(verdict.ok).toBe(false);
  });

  it("refuses a catalog signed by a non-first-party publisher", () => {
    const { sidecar } = signCatalog(catalog);
    // Expected fingerprint differs from the signer's.
    const verdict = verifyOfficialCatalogSignature(catalog, sidecar, "a".repeat(32));
    expect(verdict.ok).toBe(false);
  });

  it("refuses when the signature bytes are swapped", () => {
    const { sidecar, fingerprint } = signCatalog(catalog);
    const bytes = Buffer.from(sidecar.signature, "base64");
    bytes[0] ^= 0x01;
    const verdict = verifyOfficialCatalogSignature(
      catalog,
      { ...sidecar, signature: bytes.toString("base64") },
      fingerprint,
    );
    expect(verdict.ok).toBe(false);
  });
});

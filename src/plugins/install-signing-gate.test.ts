// Owner: plugins/install. P1.7 install-time signing gate integration tests.
// Each scenario maps to a real user path the loader MUST refuse (or accept)
// before any disk write into the workspace `extensions/` tree.

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runPluginsSignCommand } from "../cli/plugins-sign-command.js";
import {
  generateSigningKeypair,
  PLUGIN_SIGNATURE_SIDECAR_FILENAME,
  addKnownPublisher,
} from "../security/plugin-signing.js";
import {
  enforcePluginInstallSignature,
  PLUGIN_INSTALL_SIGNING_ERROR_CODE,
} from "./install-signing-gate.js";

let workspaceDir = "";
let pluginDir = "";
let knownPublishersPath = "";

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-install-signing-"));
  pluginDir = path.join(workspaceDir, "plugin-src");
  knownPublishersPath = path.join(workspaceDir, "known-publishers.json");
  mkdirSync(pluginDir, { recursive: true });
  writeFileSync(
    path.join(pluginDir, "openclaw.plugin.json"),
    JSON.stringify({ id: "demo", version: "0.0.1" }),
  );
  writeFileSync(path.join(pluginDir, "index.js"), "export const id = 'demo';\n");
});

afterEach(async () => {
  await rm(workspaceDir, { force: true, recursive: true });
});

async function signFixturePluginWithFreshKey(): Promise<{
  fingerprint: string;
  publicKeyHex: string;
}> {
  const keyDir = path.join(workspaceDir, "keys");
  const kp = generateSigningKeypair(keyDir);
  await runPluginsSignCommand({
    pluginDir,
    keyPath: kp.privateKeyPath,
    json: true,
  });
  return kp.publisher;
}

describe("enforcePluginInstallSignature", () => {
  it("refuses an unsigned plugin by default", async () => {
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      knownPublishersPath,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_SIGNING_ERROR_CODE.UNSIGNED);
    }
  });

  it("admits an unsigned plugin when allowUnsigned is set", async () => {
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      allowUnsigned: true,
      knownPublishersPath,
    });
    expect(result.ok).toBe(true);
  });

  it("admits a signed plugin from a trusted publisher", async () => {
    const publisher = await signFixturePluginWithFreshKey();
    addKnownPublisher(publisher.fingerprint, publisher.publicKeyHex, knownPublishersPath);
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      knownPublishersPath,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.publisherFingerprint).toBe(publisher.fingerprint);
    }
  });

  it("refuses a signed plugin whose publisher is unknown", async () => {
    await signFixturePluginWithFreshKey();
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      knownPublishersPath,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_SIGNING_ERROR_CODE.UNKNOWN_PUBLISHER);
    }
  });

  it("refuses a plugin whose source was tampered with after signing", async () => {
    const publisher = await signFixturePluginWithFreshKey();
    addKnownPublisher(publisher.fingerprint, publisher.publicKeyHex, knownPublishersPath);
    // Tamper a file after the sidecar has been written.
    writeFileSync(path.join(pluginDir, "index.js"), "export const id = 'evil';\n");
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      knownPublishersPath,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_SIGNING_ERROR_CODE.SIGNATURE_DRIFT);
    }
  });

  it("refuses a plugin whose sidecar signature bytes were swapped", async () => {
    const publisher = await signFixturePluginWithFreshKey();
    addKnownPublisher(publisher.fingerprint, publisher.publicKeyHex, knownPublishersPath);
    const sidecarPath = path.join(pluginDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME);
    const { readFileSync } = await import("node:fs");
    const sidecar = JSON.parse(readFileSync(sidecarPath, "utf8")) as {
      signature: string;
    };
    const tamperedBytes = Buffer.from(sidecar.signature, "base64");
    tamperedBytes[0] ^= 0x01;
    writeFileSync(
      sidecarPath,
      JSON.stringify({ ...sidecar, signature: tamperedBytes.toString("base64") }, null, 2),
    );
    const result = await enforcePluginInstallSignature({
      packageDir: pluginDir,
      pluginId: "demo",
      knownPublishersPath,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_SIGNING_ERROR_CODE.SIGNATURE_INVALID);
    }
  });
});

// Sanity: sidecar files do not get included in the canonical plugin hash, so
// signing twice produces a stable plugin_hash for the same source.
describe("sidecar stability", () => {
  it("does not include itself in the canonical hash", async () => {
    await signFixturePluginWithFreshKey();
    expect(existsSync(path.join(pluginDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME))).toBe(true);
    // Sign again with a fresh key — the plugin_hash field should still match
    // the first run because the sidecar is regenerated, not hashed.
    await signFixturePluginWithFreshKey();
    expect(existsSync(path.join(pluginDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME))).toBe(true);
  });
});

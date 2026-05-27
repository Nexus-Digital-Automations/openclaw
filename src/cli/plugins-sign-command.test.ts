// Owner: cli/plugin-signing. Smoke + security tests for the three publisher-
// side P1.7 commands. We test the entry points directly (no commander wiring)
// so failures here mean a real signing/verify break, not a CLI parser drift.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defaultRuntime } from "../runtime.js";
import {
  PLUGIN_SIGNATURE_SIDECAR_FILENAME,
  loadKnownPublishers,
  parsePluginSignatureSidecar,
  verifyPluginSignature,
} from "../security/plugin-signing.js";
import {
  runPluginsGenerateKeyCommand,
  runPluginsSignCommand,
  runPluginsTrustCommand,
} from "./plugins-sign-command.js";

let workspaceDir = "";

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-plugins-sign-cmd-"));
  vi.spyOn(defaultRuntime, "log").mockImplementation(() => {});
  vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(workspaceDir, { force: true, recursive: true });
});

function writeMinimalPlugin(pluginDir: string): void {
  writeFileSync(
    path.join(pluginDir, "openclaw.plugin.json"),
    JSON.stringify({ id: "demo", version: "0.0.1" }),
  );
  writeFileSync(path.join(pluginDir, "index.js"), "export const id = 'demo';\n");
}

describe("runPluginsGenerateKeyCommand", () => {
  it("writes private and public PEMs at the requested directory", () => {
    const outDir = path.join(workspaceDir, "keys");
    runPluginsGenerateKeyCommand({ outDir, json: true });
    expect(existsSync(path.join(outDir, "private.pem"))).toBe(true);
    expect(existsSync(path.join(outDir, "public.pem"))).toBe(true);
  });
});

describe("runPluginsSignCommand", () => {
  it("writes a verifiable openclaw.plugin.sig sidecar next to the manifest", async () => {
    const keyDir = path.join(workspaceDir, "keys");
    runPluginsGenerateKeyCommand({ outDir: keyDir, json: true });
    const pluginDir = path.join(workspaceDir, "plugin");
    mkdirSync(pluginDir, { recursive: true });
    writeMinimalPlugin(pluginDir);
    await runPluginsSignCommand({
      pluginDir,
      keyPath: path.join(keyDir, "private.pem"),
      json: true,
    });
    const sidecarPath = path.join(pluginDir, PLUGIN_SIGNATURE_SIDECAR_FILENAME);
    expect(existsSync(sidecarPath)).toBe(true);
    const sidecar = parsePluginSignatureSidecar(readFileSync(sidecarPath, "utf8"));
    expect(sidecar.plugin_hash).toMatch(/^[a-f0-9]{64}$/u);
    const verifyResult = verifyPluginSignature(sidecar.plugin_hash, sidecar);
    expect(verifyResult.ok).toBe(true);
  });
});

describe("runPluginsTrustCommand", () => {
  it("appends a publisher to a custom known-publishers file", () => {
    const registryPath = path.join(workspaceDir, "known-publishers.json");
    runPluginsTrustCommand({
      fingerprint: "a".repeat(32),
      publicKeyHex: "deadbeef",
      filePath: registryPath,
      json: true,
    });
    const loaded = loadKnownPublishers(registryPath);
    expect(loaded).toEqual([{ fingerprint: "a".repeat(32), publicKeyHex: "deadbeef" }]);
  });
});

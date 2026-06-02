/**
 * Owner: plugin-sdk/fs-guard-runtime.test
 *
 * Spec: E.4 — pluginReadFile / pluginWriteFile / pluginListDir bound
 * plugin filesystem access to the manifest's declared fsScopes.
 *
 * Invariants:
 *  - No registered capabilities → throws (no declared fsScopes)
 *  - Declared scope present → access proceeds
 *  - Declared scope absent → throws + does NOT touch disk
 *  - Each helper exercises its own scope independently
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearPluginCapabilitiesForTests, setPluginCapabilities } from "../plugins/capabilities.js";
import {
  FsScopeDeniedError,
  pluginListDir,
  pluginReadFile,
  pluginWriteFile,
} from "./fs-guard-runtime.js";

let tempDir: string;
let sampleFile: string;

beforeEach(async () => {
  clearPluginCapabilitiesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-fs-guard-"));
  sampleFile = path.join(tempDir, "sample.txt");
  await fs.writeFile(sampleFile, "stored content", "utf8");
});

afterEach(async () => {
  clearPluginCapabilitiesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("pluginReadFile — fsScope.read enforcement", () => {
  it("throws when the plugin has no registered capabilities", async () => {
    await expect(
      pluginReadFile({ pluginId: "plugin-empty", scope: "workspace.read", filePath: sampleFile }),
    ).rejects.toBeInstanceOf(FsScopeDeniedError);
  });

  it("reads the file when the plugin declared the required scope", async () => {
    setPluginCapabilities("plugin-reader", { fsScopes: ["workspace.read"] });
    const content = await pluginReadFile({
      pluginId: "plugin-reader",
      scope: "workspace.read",
      filePath: sampleFile,
    });
    expect(content).toBe("stored content");
  });

  it("refuses when the plugin's fsScopes do not include the requested scope", async () => {
    setPluginCapabilities("plugin-writer-only", { fsScopes: ["workspace.write"] });
    await expect(
      pluginReadFile({
        pluginId: "plugin-writer-only",
        scope: "workspace.read",
        filePath: sampleFile,
      }),
    ).rejects.toBeInstanceOf(FsScopeDeniedError);
  });
});

describe("pluginWriteFile — fsScope.write enforcement", () => {
  it("writes the file when the plugin declared workspace.write", async () => {
    setPluginCapabilities("plugin-writer", { fsScopes: ["workspace.write"] });
    const target = path.join(tempDir, "fresh.txt");
    await pluginWriteFile({
      pluginId: "plugin-writer",
      scope: "workspace.write",
      filePath: target,
      contents: "new content",
    });
    expect(await fs.readFile(target, "utf8")).toBe("new content");
  });

  it("refuses + does NOT create the file when scope is missing", async () => {
    setPluginCapabilities("plugin-reader-only", { fsScopes: ["workspace.read"] });
    const target = path.join(tempDir, "should-not-exist.txt");
    await expect(
      pluginWriteFile({
        pluginId: "plugin-reader-only",
        scope: "workspace.write",
        filePath: target,
        contents: "never written",
      }),
    ).rejects.toBeInstanceOf(FsScopeDeniedError);
    const targetExists = await fs
      .access(target)
      .then(() => true)
      .catch(() => false);
    expect(targetExists).toBe(false);
  });
});

describe("pluginListDir — fsScope.read enforcement", () => {
  it("lists when the plugin declared the required read scope", async () => {
    setPluginCapabilities("plugin-reader", { fsScopes: ["workspace.read"] });
    const entries = await pluginListDir({
      pluginId: "plugin-reader",
      scope: "workspace.read",
      dirPath: tempDir,
    });
    expect(entries).toContain("sample.txt");
  });

  it("refuses when scope is missing", async () => {
    setPluginCapabilities("plugin-no-fs", { fsScopes: [] });
    await expect(
      pluginListDir({ pluginId: "plugin-no-fs", scope: "workspace.read", dirPath: tempDir }),
    ).rejects.toBeInstanceOf(FsScopeDeniedError);
  });
});

describe("FsScopeDeniedError — forensic fields", () => {
  it("attaches pluginId + scope + reason to the thrown error", async () => {
    setPluginCapabilities("plugin-strict", { fsScopes: ["workspace.read"] });
    try {
      await pluginWriteFile({
        pluginId: "plugin-strict",
        scope: "workspace.write",
        filePath: path.join(tempDir, "nope.txt"),
        contents: "x",
      });
      expect.unreachable("expected FsScopeDeniedError");
    } catch (err) {
      expect(err).toBeInstanceOf(FsScopeDeniedError);
      if (err instanceof FsScopeDeniedError) {
        expect(err.pluginId).toBe("plugin-strict");
        expect(err.scope).toBe("workspace.write");
        expect(err.reason).toContain("fs scope");
      }
    }
  });
});

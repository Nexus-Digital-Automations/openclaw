// Owner: plugins/integrity. Critical-path security tests for plugins.lock:
// drift detection MUST never silently pass. Each spec describes a tampering
// scenario the loader is expected to refuse at enable time.

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  hashPluginSourceFile,
  hashPluginSourceTree,
  PluginsLockHashMismatchError,
  PluginsLockMissingFileError,
  PluginsLockUnexpectedFileError,
  PluginsLockUnknownPluginError,
  PluginsLockUnsafePathError,
  PluginsLockVerificationError,
  readPluginsLock,
  resolvePluginsLockPath,
  verifyPluginAtLoad,
  verifyPluginSourceAgainstLock,
  writePluginsLock,
  type PluginsLockPlugin,
} from "./plugins-lock.js";

let workspaceDir = "";

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-plugins-lock-"));
});

afterEach(async () => {
  await rm(workspaceDir, { force: true, recursive: true });
});

async function writePluginSourceFile(
  pluginRoot: string,
  relative: string,
  body: string,
): Promise<void> {
  const abs = path.join(pluginRoot, relative);
  await writeFile(abs, body, "utf8");
}

async function lockEntryFor(
  absPath: string,
  body: string,
): Promise<{
  sha256: string;
  size: number;
}> {
  return {
    sha256: await hashPluginSourceFile(absPath),
    size: Buffer.byteLength(body, "utf8"),
  };
}

describe("hashPluginSourceFile", () => {
  it("returns deterministic sha256 for the same bytes across calls", async () => {
    const file = path.join(workspaceDir, "fixture.ts");
    await writeFile(file, "export const x = 1;", "utf8");
    const first = await hashPluginSourceFile(file);
    const second = await hashPluginSourceFile(file);
    expect(first).toBe(second);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("writePluginsLock / readPluginsLock round-trip", () => {
  it("writes deterministic JSON sorted by pluginId and file key", async () => {
    const lockPath = path.join(workspaceDir, "plugins.lock");
    const plugins: PluginsLockPlugin[] = [
      {
        pluginId: "z-plugin",
        version: "1.0.0",
        files: {
          "b.ts": { sha256: "f".repeat(64), size: 10 },
          "a.ts": { sha256: "0".repeat(64), size: 20 },
        },
      },
      {
        pluginId: "a-plugin",
        version: "2.0.0",
        files: { "src/index.ts": { sha256: "1".repeat(64), size: 30 } },
      },
    ];
    await writePluginsLock(lockPath, { plugins, generatedAtMs: 1_700_000_000_000 });

    const raw = await readFile(lockPath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    const parsed = JSON.parse(raw);
    expect(parsed.plugins[0].pluginId).toBe("a-plugin");
    expect(parsed.plugins[1].pluginId).toBe("z-plugin");
    expect(Object.keys(parsed.plugins[1].files)).toEqual(["a.ts", "b.ts"]);

    const loaded = await readPluginsLock(lockPath);
    expect(loaded).not.toBeUndefined();
    expect(loaded?.version).toBe(1);
    expect(loaded?.plugins.length).toBe(2);
  });

  it("returns undefined when the lockfile is absent", async () => {
    const result = await readPluginsLock(path.join(workspaceDir, "plugins.lock"));
    expect(result).toBeUndefined();
  });
});

describe("readPluginsLock path safety", () => {
  async function writeRawLock(fileKey: string): Promise<string> {
    const lockPath = path.join(workspaceDir, "plugins.lock");
    const raw = {
      version: 1,
      generatedAtMs: 1_700_000_000_000,
      plugins: [
        {
          pluginId: "p1",
          version: "1.0.0",
          files: { [fileKey]: { sha256: "0".repeat(64), size: 1 } },
        },
      ],
    };
    await writeFile(lockPath, JSON.stringify(raw), "utf8");
    return lockPath;
  }

  // A tampered lock key is the only attacker-influenced value that reaches
  // path.join + stat/hash, so traversal must be refused at parse time — parity
  // with skills-lock (the regression that prompted this guard).
  it.each([
    ["../../../../etc/passwd", "parent traversal"],
    ["/etc/passwd", "absolute path"],
    ["nested/../../escape.ts", "normalized traversal"],
    ["..\\..\\windows", "backslash separator"],
  ])("rejects %s (%s) with PluginsLockUnsafePathError", async (fileKey) => {
    const lockPath = await writeRawLock(fileKey);
    await expect(readPluginsLock(lockPath)).rejects.toBeInstanceOf(PluginsLockUnsafePathError);
  });

  it("accepts a contained nested relative key", async () => {
    const lockPath = await writeRawLock("src/nested/index.ts");
    const lock = await readPluginsLock(lockPath);
    expect(lock?.plugins[0]?.files).toHaveProperty(["src/nested/index.ts"]);
  });
});

describe("resolvePluginsLockPath", () => {
  it("composes state dir + plugins/plugins.lock", () => {
    const result = resolvePluginsLockPath({ stateDir: workspaceDir });
    expect(result).toBe(path.join(workspaceDir, "plugins", "plugins.lock"));
  });

  it("honors an explicit filePath override", () => {
    const explicit = path.join(workspaceDir, "elsewhere.lock");
    expect(resolvePluginsLockPath({ filePath: explicit })).toBe(explicit);
  });
});

describe("verifyPluginSourceAgainstLock", () => {
  async function setupPluginAndLock(): Promise<{
    pluginRoot: string;
    body: string;
    lockPath: string;
  }> {
    const pluginRoot = path.join(workspaceDir, "plugin");
    const body = 'export const id = "trusted";';
    await mkdir(pluginRoot, { recursive: true });
    await writePluginSourceFile(pluginRoot, "index.ts", body);
    const lockPath = path.join(workspaceDir, "plugins.lock");
    await writePluginsLock(lockPath, {
      plugins: [
        {
          pluginId: "p1",
          version: "1.0.0",
          files: { "index.ts": await lockEntryFor(path.join(pluginRoot, "index.ts"), body) },
        },
      ],
    });
    return { pluginRoot, body, lockPath };
  }

  it("returns without throwing when every file matches", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    const lock = await readPluginsLock(lockPath);
    expect(lock).not.toBeUndefined();
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("throws PluginsLockUnknownPluginError for a plugin not in the lock", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    const lock = await readPluginsLock(lockPath);
    await expect(
      verifyPluginSourceAgainstLock(pluginRoot, "missing", lock!),
    ).rejects.toBeInstanceOf(PluginsLockUnknownPluginError);
  });

  it("throws PluginsLockHashMismatchError when a single byte of source drifts", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginSourceFile(pluginRoot, "index.ts", 'export const id = "TAMPERED";');
    const lock = await readPluginsLock(lockPath);
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      PluginsLockHashMismatchError,
    );
  });

  it("throws PluginsLockMissingFileError when a locked file is deleted", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await rm(path.join(pluginRoot, "index.ts"));
    const lock = await readPluginsLock(lockPath);
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      PluginsLockMissingFileError,
    );
  });

  it("throws PluginsLockUnexpectedFileError when a new file appears outside the lock", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginSourceFile(pluginRoot, "stowaway.ts", 'console.log("smuggled");');
    const lock = await readPluginsLock(lockPath);
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      PluginsLockUnexpectedFileError,
    );
  });

  it("ignores node_modules, dist, and other build artifacts inside the plugin root", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await mkdir(path.join(pluginRoot, "node_modules", "dep"), { recursive: true });
    await mkdir(path.join(pluginRoot, "dist"), { recursive: true });
    await writePluginSourceFile(pluginRoot, path.join("node_modules", "dep", "index.js"), "x");
    await writePluginSourceFile(pluginRoot, path.join("dist", "compiled.js"), "y");
    await writePluginSourceFile(pluginRoot, ".DS_Store", "");
    const lock = await readPluginsLock(lockPath);
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("exposes the common PluginsLockVerificationError base for one-shot catch", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginSourceFile(pluginRoot, "index.ts", 'export const id = "TAMPERED";');
    const lock = await readPluginsLock(lockPath);
    let caught: unknown;
    try {
      await verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(PluginsLockVerificationError);
  });
});

describe("hashPluginSourceTree", () => {
  it("produces an entry map that verifyPluginSourceAgainstLock accepts byte-for-byte", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(pluginRoot, { recursive: true });
    await writeFile(path.join(pluginRoot, "a.ts"), "body-a", "utf8");
    await writeFile(path.join(pluginRoot, "b.ts"), "body-b", "utf8");
    const files = await hashPluginSourceTree(pluginRoot);
    const lockPath = path.join(workspaceDir, "plugins.lock");
    await writePluginsLock(lockPath, {
      plugins: [{ pluginId: "p1", version: "1.0.0", files }],
    });
    const lock = await readPluginsLock(lockPath);
    await expect(verifyPluginSourceAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("ignores build artifacts the same way verify does", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(path.join(pluginRoot, "node_modules", "dep"), { recursive: true });
    await mkdir(path.join(pluginRoot, "dist"), { recursive: true });
    await writeFile(path.join(pluginRoot, "index.ts"), "body", "utf8");
    await writeFile(path.join(pluginRoot, "node_modules", "dep", "index.js"), "skip", "utf8");
    await writeFile(path.join(pluginRoot, "dist", "compiled.js"), "skip", "utf8");
    await writeFile(path.join(pluginRoot, ".DS_Store"), "", "utf8");
    const files = await hashPluginSourceTree(pluginRoot);
    expect(Object.keys(files)).toEqual(["index.ts"]);
  });
});

describe("verifyPluginAtLoad", () => {
  it("returns silently when no lockfile is present (opt-out workspace)", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(pluginRoot, { recursive: true });
    await writeFile(path.join(pluginRoot, "index.ts"), "body", "utf8");
    await expect(
      verifyPluginAtLoad({
        pluginRoot,
        pluginId: "p1",
        lockPath: path.join(workspaceDir, "missing.lock"),
      }),
    ).resolves.toBeUndefined();
  });

  it("throws PluginsLockHashMismatchError when source drifts since lock time", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(pluginRoot, { recursive: true });
    await writeFile(path.join(pluginRoot, "index.ts"), "original", "utf8");
    const files = await hashPluginSourceTree(pluginRoot);
    const lockPath = path.join(workspaceDir, "plugins.lock");
    await writePluginsLock(lockPath, {
      plugins: [{ pluginId: "p1", version: "1.0.0", files }],
    });
    await writeFile(path.join(pluginRoot, "index.ts"), "tampered", "utf8");
    await expect(
      verifyPluginAtLoad({ pluginRoot, pluginId: "p1", lockPath }),
    ).rejects.toBeInstanceOf(PluginsLockHashMismatchError);
  });
});

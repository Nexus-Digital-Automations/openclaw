import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  hashPluginFiles,
  hashSkillFile,
  readSkillsLock,
  resolveSkillsLockPath,
  SkillsLockHashMismatchError,
  SkillsLockMissingFileError,
  SkillsLockUnexpectedFileError,
  SkillsLockUnknownPluginError,
  SkillsLockUnsafePathError,
  SkillsLockVerificationError,
  verifyPluginAgainstLock,
  writeSkillsLock,
  type SkillsLockPlugin,
} from "./skills-lock.js";

let workspaceDir = "";

beforeEach(async () => {
  workspaceDir = await mkdtemp(path.join(os.tmpdir(), "openclaw-skills-lock-"));
});

afterEach(async () => {
  await rm(workspaceDir, { force: true, recursive: true });
});

async function writePluginFile(pluginRoot: string, relative: string, body: string): Promise<void> {
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
    sha256: await hashSkillFile(absPath),
    size: Buffer.byteLength(body, "utf8"),
  };
}

describe("hashSkillFile", () => {
  it("returns deterministic sha256 for the same bytes across calls", async () => {
    const file = path.join(workspaceDir, "fixture.txt");
    await writeFile(file, "deterministic-bytes", "utf8");
    const first = await hashSkillFile(file);
    const second = await hashSkillFile(file);
    expect(first).toBe(second);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("writeSkillsLock / readSkillsLock round-trip", () => {
  it("writes deterministic JSON and reads it back identically", async () => {
    const lockPath = path.join(workspaceDir, "skills.lock");
    const plugins: SkillsLockPlugin[] = [
      {
        pluginId: "z-plugin",
        version: "1.0.0",
        files: {
          "b.md": { sha256: "f".repeat(64), size: 10 },
          "a.md": { sha256: "0".repeat(64), size: 20 },
        },
      },
      {
        pluginId: "a-plugin",
        version: "2.0.0",
        files: { "skill.md": { sha256: "1".repeat(64), size: 30 } },
      },
    ];
    await writeSkillsLock(lockPath, { plugins, generatedAtMs: 1_700_000_000_000 });

    const raw = await readFile(lockPath, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    const parsed = JSON.parse(raw);
    expect(parsed.plugins[0].pluginId).toBe("a-plugin");
    expect(parsed.plugins[1].pluginId).toBe("z-plugin");
    expect(Object.keys(parsed.plugins[1].files)).toEqual(["a.md", "b.md"]);

    const loaded = await readSkillsLock(lockPath);
    expect(loaded).not.toBeUndefined();
    expect(loaded?.version).toBe(1);
    expect(loaded?.plugins.length).toBe(2);
  });

  it("returns undefined when the lockfile is absent", async () => {
    const result = await readSkillsLock(path.join(workspaceDir, "skills.lock"));
    expect(result).toBeUndefined();
  });
});

describe("readSkillsLock path safety", () => {
  async function writeRawLock(fileKey: string): Promise<string> {
    const lockPath = path.join(workspaceDir, "skills.lock");
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
  // path.join + stat/hash, so traversal must be refused at parse time.
  it.each([
    ["../../../../etc/passwd", "parent traversal"],
    ["/etc/passwd", "absolute path"],
    ["nested/../../escape.md", "normalized traversal"],
    ["..\\..\\windows", "backslash separator"],
  ])("rejects %s (%s) with SkillsLockUnsafePathError", async (fileKey) => {
    const lockPath = await writeRawLock(fileKey);
    await expect(readSkillsLock(lockPath)).rejects.toBeInstanceOf(SkillsLockUnsafePathError);
  });

  it("accepts a contained nested relative key", async () => {
    const lockPath = await writeRawLock("docs/nested/skill.md");
    const lock = await readSkillsLock(lockPath);
    expect(lock?.plugins[0]?.files).toHaveProperty(["docs/nested/skill.md"]);
  });
});

describe("resolveSkillsLockPath", () => {
  it("composes state dir + plugins/skills.lock", () => {
    const result = resolveSkillsLockPath({ stateDir: workspaceDir });
    expect(result).toBe(path.join(workspaceDir, "plugins", "skills.lock"));
  });

  it("honors an explicit filePath override", () => {
    const explicit = path.join(workspaceDir, "elsewhere.lock");
    expect(resolveSkillsLockPath({ filePath: explicit })).toBe(explicit);
  });
});

describe("verifyPluginAgainstLock", () => {
  async function setupPluginAndLock(): Promise<{
    pluginRoot: string;
    body: string;
    lockPath: string;
  }> {
    const pluginRoot = path.join(workspaceDir, "plugin");
    const body = "trusted-skill-body";
    await mkdir(pluginRoot, { recursive: true });
    await writePluginFile(pluginRoot, "skill.md", body);
    const lockPath = path.join(workspaceDir, "skills.lock");
    await writeSkillsLock(lockPath, {
      plugins: [
        {
          pluginId: "p1",
          version: "1.0.0",
          files: { "skill.md": await lockEntryFor(path.join(pluginRoot, "skill.md"), body) },
        },
      ],
    });
    return { pluginRoot, body, lockPath };
  }

  it("returns without throwing when every file matches", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    const lock = await readSkillsLock(lockPath);
    expect(lock).not.toBeUndefined();
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("throws SkillsLockUnknownPluginError for a plugin not in the lock", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "missing", lock!)).rejects.toBeInstanceOf(
      SkillsLockUnknownPluginError,
    );
  });

  it("throws SkillsLockHashMismatchError when a file's bytes drift", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginFile(pluginRoot, "skill.md", "tampered-body");
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      SkillsLockHashMismatchError,
    );
  });

  it("throws SkillsLockMissingFileError when a locked file is deleted", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await rm(path.join(pluginRoot, "skill.md"));
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      SkillsLockMissingFileError,
    );
  });

  it("throws SkillsLockUnexpectedFileError when a new file appears outside the lock", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginFile(pluginRoot, "stowaway.md", "new-content");
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).rejects.toBeInstanceOf(
      SkillsLockUnexpectedFileError,
    );
  });

  it("ignores node_modules and other infrastructure files inside the plugin root", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await mkdir(path.join(pluginRoot, "node_modules", "dep"), { recursive: true });
    await writePluginFile(pluginRoot, path.join("node_modules", "dep", "index.js"), "irrelevant");
    await writePluginFile(pluginRoot, ".DS_Store", "");
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("exposes the common SkillsLockVerificationError base for one-shot catch", async () => {
    const { pluginRoot, lockPath } = await setupPluginAndLock();
    await writePluginFile(pluginRoot, "skill.md", "tampered-body");
    const lock = await readSkillsLock(lockPath);
    let caught: unknown;
    try {
      await verifyPluginAgainstLock(pluginRoot, "p1", lock!);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(SkillsLockVerificationError);
  });
});

describe("hashPluginFiles", () => {
  it("produces an entry map that verifyPluginAgainstLock accepts byte-for-byte", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(pluginRoot, { recursive: true });
    await writeFile(path.join(pluginRoot, "a.md"), "body-a", "utf8");
    await writeFile(path.join(pluginRoot, "b.md"), "body-b", "utf8");
    const files = await hashPluginFiles(pluginRoot);
    const lockPath = path.join(workspaceDir, "skills.lock");
    await writeSkillsLock(lockPath, {
      plugins: [{ pluginId: "p1", version: "1.0.0", files }],
    });
    const lock = await readSkillsLock(lockPath);
    await expect(verifyPluginAgainstLock(pluginRoot, "p1", lock!)).resolves.toBeUndefined();
  });

  it("ignores node_modules and infrastructure files the same way verify does", async () => {
    const pluginRoot = path.join(workspaceDir, "plugin");
    await mkdir(path.join(pluginRoot, "node_modules", "dep"), { recursive: true });
    await writeFile(path.join(pluginRoot, "skill.md"), "body", "utf8");
    await writeFile(path.join(pluginRoot, "node_modules", "dep", "index.js"), "irrelevant", "utf8");
    await writeFile(path.join(pluginRoot, ".DS_Store"), "", "utf8");
    const files = await hashPluginFiles(pluginRoot);
    expect(Object.keys(files)).toEqual(["skill.md"]);
  });
});

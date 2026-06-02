import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  classifyZone,
  classifyZoneWithResolvedConfig,
  resolveWorkspaceZoneConfig,
} from "./workspace-zones.js";

const FAKE_HOME = "/fake/home";
const FAKE_UNTRUSTED = path.join(FAKE_HOME, ".openclaw", "untrusted");

function withFakeHome(): { env: NodeJS.ProcessEnv; homedir: () => string } {
  return { env: { ...process.env, HOME: FAKE_HOME }, homedir: () => FAKE_HOME };
}

describe("classifyZone (default untrusted root)", () => {
  it("classifies a path inside ~/.openclaw/untrusted as untrusted", () => {
    const target = path.join(FAKE_UNTRUSTED, "downloads", "model-output.md");
    expect(classifyZone(target, withFakeHome())).toBe("untrusted");
  });

  it("classifies the untrusted root itself as untrusted", () => {
    expect(classifyZone(FAKE_UNTRUSTED, withFakeHome())).toBe("untrusted");
  });

  it("classifies a sibling of ~/.openclaw/untrusted as trusted", () => {
    const target = path.join(FAKE_HOME, ".openclaw", "skills", "verified.md");
    expect(classifyZone(target, withFakeHome())).toBe("trusted");
  });

  it("classifies an unrelated absolute path as trusted", () => {
    expect(classifyZone(path.resolve(os.tmpdir(), "anywhere.txt"), withFakeHome())).toBe("trusted");
  });

  // M4: on a case-insensitive filesystem a case-variant path resolves to the
  // same file, so it must still classify as untrusted (injected, so the test is
  // deterministic on case-sensitive Linux CI).
  it("classifies a case-variant untrusted path as untrusted when case-insensitive", () => {
    const target = path.join(FAKE_HOME, ".openclaw", "UNTRUSTED", "model-output.md");
    expect(classifyZone(target, { ...withFakeHome(), caseInsensitive: true })).toBe("untrusted");
  });

  it("keeps case-variant paths distinct on a case-sensitive filesystem", () => {
    const target = path.join(FAKE_HOME, ".openclaw", "UNTRUSTED", "model-output.md");
    expect(classifyZone(target, { ...withFakeHome(), caseInsensitive: false })).toBe("trusted");
  });
});

describe("classifyZone fail-safe behavior", () => {
  it("classifies an empty path as untrusted", () => {
    expect(classifyZone("", withFakeHome())).toBe("untrusted");
  });

  it("classifies a relative path as untrusted", () => {
    expect(classifyZone("relative/file.txt", withFakeHome())).toBe("untrusted");
  });

  it("does not let a similarly-prefixed-but-outside path slip into the zone", () => {
    const sibling = path.join(FAKE_HOME, ".openclaw", "untrusted-but-not-really.md");
    expect(classifyZone(sibling, withFakeHome())).toBe("trusted");
  });
});

describe("classifyZone with explicit untrustedRoots override", () => {
  it("uses the override roots instead of the default", () => {
    const customRoot = path.resolve("/tmp/my-untrusted-zone");
    expect(classifyZone(path.join(customRoot, "skill.md"), { untrustedRoots: [customRoot] })).toBe(
      "untrusted",
    );
  });

  it("does not consult the default root when overrides are set", () => {
    const customRoot = path.resolve("/tmp/some-untrusted-zone");
    expect(
      classifyZone(path.join(FAKE_UNTRUSTED, "model-output.md"), {
        untrustedRoots: [customRoot],
        ...withFakeHome(),
      }),
    ).toBe("trusted");
  });

  it("matches any of multiple override roots", () => {
    const rootA = path.resolve("/tmp/zone-a");
    const rootB = path.resolve("/tmp/zone-b");
    const opts = { untrustedRoots: [rootA, rootB] };
    expect(classifyZone(path.join(rootA, "file.md"), opts)).toBe("untrusted");
    expect(classifyZone(path.join(rootB, "file.md"), opts)).toBe("untrusted");
    expect(classifyZone(path.resolve("/tmp/zone-c/file.md"), opts)).toBe("trusted");
  });
});

describe("resolveWorkspaceZoneConfig + classifyZoneWithResolvedConfig", () => {
  it("produces identical decisions to the all-in-one classifyZone for the same options", () => {
    const opts = withFakeHome();
    const resolved = resolveWorkspaceZoneConfig(opts);
    const inside = path.join(FAKE_UNTRUSTED, "x.md");
    const outside = path.join(FAKE_HOME, "outside.md");
    expect(classifyZoneWithResolvedConfig(inside, resolved)).toBe(classifyZone(inside, opts));
    expect(classifyZoneWithResolvedConfig(outside, resolved)).toBe(classifyZone(outside, opts));
  });

  it("preserves fail-safe defaults under the pre-resolved variant", () => {
    const resolved = resolveWorkspaceZoneConfig(withFakeHome());
    expect(classifyZoneWithResolvedConfig("", resolved)).toBe("untrusted");
    expect(classifyZoneWithResolvedConfig("relative", resolved)).toBe("untrusted");
  });
});

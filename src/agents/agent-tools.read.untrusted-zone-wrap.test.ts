import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AgentToolResult } from "openclaw/plugin-sdk/agent-core";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createOpenClawReadTool } from "./agent-tools.read.js";
import type { AnyAgentTool } from "./agent-tools.types.js";

let tmpHome = "";
let originalHome: string | undefined;

beforeAll(async () => {
  // realpath dereferences the macOS /tmp -> /private/tmp symlink so that
  // process.env.HOME and the resolved file paths share a single prefix.
  tmpHome = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-read-zone-")));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
});

afterAll(async () => {
  if (originalHome === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = originalHome;
  }
  await fs.rm(tmpHome, { force: true, recursive: true });
});

function makeStubBase(executeResult: AgentToolResult<unknown>): {
  base: AnyAgentTool;
  execute: ReturnType<typeof vi.fn>;
} {
  const execute = vi.fn(async () => executeResult);
  const base = {
    name: "read",
    description: "stub read",
    inputSchema: { type: "object", properties: {} },
    execute,
  } as unknown as AnyAgentTool;
  return { base, execute };
}

describe("createOpenClawReadTool untrusted-zone wrap", () => {
  it("wraps text content in external-content markers when reading an untrusted-zone path", async () => {
    const untrustedPath = path.join(tmpHome, ".openclaw", "untrusted", "model-out.md");
    const { base } = makeStubBase({
      content: [{ type: "text", text: "model-emitted body" }],
      details: undefined,
    });
    const tool = createOpenClawReadTool(base);
    const result = await tool.execute("tc1", { path: untrustedPath }, new AbortController().signal);
    const textBlock = result.content.find((b) => b.type === "text");
    expect(textBlock).toBeDefined();
    expect(textBlock?.text).toContain("EXTERNAL_UNTRUSTED_CONTENT");
    expect(textBlock?.text).toContain("END_EXTERNAL_UNTRUSTED_CONTENT");
    expect(textBlock?.text).toContain('source="untrusted_zone"');
    expect(textBlock?.text).toContain("model-emitted body");
  });

  it("does not wrap text content when reading a trusted path", async () => {
    const trustedPath = path.join(tmpHome, "workspace", "doc.md");
    const { base } = makeStubBase({
      content: [{ type: "text", text: "trusted body" }],
      details: undefined,
    });
    const tool = createOpenClawReadTool(base);
    const result = await tool.execute("tc2", { path: trustedPath }, new AbortController().signal);
    const textBlock = result.content.find((b) => b.type === "text");
    expect(textBlock?.text).toBe("trusted body");
    expect(textBlock?.text).not.toContain("OpenClaw:ExternalContent:start");
  });

  // L3: a symlink in a trusted zone whose realpath resolves into the untrusted
  // root must be wrapped — the classifier checks the resolved target, not just
  // the lexical path.
  it("wraps when a trusted-zone path symlinks into the untrusted root", async () => {
    const untrustedTarget = path.join(tmpHome, ".openclaw", "untrusted", "evil.md");
    await fs.mkdir(path.dirname(untrustedTarget), { recursive: true });
    await fs.writeFile(untrustedTarget, "laundered body", "utf8");
    const trustedLink = path.join(tmpHome, "workspace", "note.md");
    await fs.mkdir(path.dirname(trustedLink), { recursive: true });
    await fs.symlink(untrustedTarget, trustedLink);
    const { base } = makeStubBase({
      content: [{ type: "text", text: "laundered body" }],
      details: undefined,
    });
    const tool = createOpenClawReadTool(base);
    const result = await tool.execute(
      "tc-sym",
      { path: trustedLink },
      new AbortController().signal,
    );
    const textBlock = result.content.find((b) => b.type === "text");
    expect(textBlock?.text).toContain("EXTERNAL_UNTRUSTED_CONTENT");
  });

  it("does not wrap when the path parameter is missing or relative", async () => {
    const { base } = makeStubBase({
      content: [{ type: "text", text: "relative body" }],
      details: undefined,
    });
    const tool = createOpenClawReadTool(base);
    const result = await tool.execute(
      "tc3",
      { path: "relative/file.md" },
      new AbortController().signal,
    );
    const textBlock = result.content.find((b) => b.type === "text");
    expect(textBlock?.text).toBe("relative body");
  });
});

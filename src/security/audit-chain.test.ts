/**
 * Owner: security/audit-chain.
 *
 * Spec: hash-chained audit log preserves integrity across appends,
 * detects tampering, and survives concurrent writes from one process.
 */
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { appendAuditEntry, computeArgvHash, verifyAuditChain } from "./audit-chain.js";

let tmpDir = "";
let logPath = "";

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-chain-"));
  logPath = path.join(tmpDir, "audit-chain.ndjson");
});

afterEach(async () => {
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("audit-chain", () => {
  it("computes deterministic argvHash regardless of key order", () => {
    const a = computeArgvHash({ b: 2, a: 1, nested: { y: [3, 4], x: "v" } });
    const b = computeArgvHash({ nested: { x: "v", y: [3, 4] }, a: 1, b: 2 });
    expect(a).toBe(b);
    expect(a).toHaveLength(64);
  });

  it("appends three entries and verifies the chain", async () => {
    for (let i = 0; i < 3; i++) {
      await appendAuditEntry({
        entryId: `e-${i}`,
        toolName: "demo_tool",
        argv: { index: i, label: `step-${i}` },
        logPath,
      });
    }
    const result = await verifyAuditChain(logPath);
    expect(result).toEqual({ ok: true });
  });

  it("detects a single-byte tamper mid-chain", async () => {
    for (let i = 0; i < 3; i++) {
      await appendAuditEntry({
        entryId: `e-${i}`,
        toolName: "demo_tool",
        argv: { index: i },
        logPath,
      });
    }
    const original = await fs.readFile(logPath, "utf8");
    const lines = original.split("\n");
    const target = lines[1] ?? "";
    const flipped = target.replace(/"toolName":"demo_tool"/, '"toolName":"demo_toox"');
    lines[1] = flipped;
    await fs.writeFile(logPath, lines.join("\n"), "utf8");
    const result = await verifyAuditChain(logPath);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.brokenAt).toBe(2);
      expect(result.reason).toContain("prevLogHash");
    }
  });

  it("preserves chain integrity under concurrent appends", async () => {
    const count = 50;
    await Promise.all(
      Array.from({ length: count }, (_, i) =>
        appendAuditEntry({
          entryId: `e-${i}`,
          toolName: "demo_tool",
          argv: { index: i },
          logPath,
        }),
      ),
    );
    const content = await fs.readFile(logPath, "utf8");
    const lines = content.trimEnd().split("\n");
    expect(lines).toHaveLength(count);
    const result = await verifyAuditChain(logPath);
    expect(result).toEqual({ ok: true });
  });

  it("returns ok for a missing log file", async () => {
    const result = await verifyAuditChain(path.join(tmpDir, "absent.ndjson"));
    expect(result).toEqual({ ok: true });
  });
});

describe("audit-chain tip anchor (M1: tail truncation / erasure)", () => {
  let stateDir = "";
  let prevStateDir: string | undefined;

  beforeEach(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "audit-state-"));
    prevStateDir = process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_STATE_DIR = stateDir;
    closeOpenClawStateDatabase();
  });

  afterEach(async () => {
    closeOpenClawStateDatabase();
    if (prevStateDir === undefined) {
      delete process.env.OPENCLAW_STATE_DIR;
    } else {
      process.env.OPENCLAW_STATE_DIR = prevStateDir;
    }
    await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("detects tail truncation the bare hash chain misses", async () => {
    for (let i = 0; i < 3; i++) {
      await appendAuditEntry({ entryId: `e-${i}`, toolName: "demo", argv: { i }, logPath });
    }
    expect((await verifyAuditChain(logPath)).ok).toBe(true);
    // Drop the last entry — still a valid prefix the bare chain accepts.
    const lines = (await fs.readFile(logPath, "utf8")).trimEnd().split("\n");
    await fs.writeFile(logPath, `${lines.slice(0, -1).join("\n")}\n`, "utf8");
    expect((await verifyAuditChain(logPath)).ok).toBe(false);
  });

  it("detects full erasure of a non-empty log", async () => {
    await appendAuditEntry({ entryId: "e-0", toolName: "demo", argv: {}, logPath });
    await fs.rm(logPath);
    expect((await verifyAuditChain(logPath)).ok).toBe(false);
  });
});

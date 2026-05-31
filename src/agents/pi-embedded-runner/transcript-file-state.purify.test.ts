/**
 * Owner: agents/pi-embedded-runner/transcript-file-state.purify.test
 *
 * Spec: D.3 part 2 — readTranscriptFileState routes the post-parse Pi
 * SessionEntry array through maybePurifySessionEntries when callers
 * supply purification context. The disk transcript is never rewritten.
 *
 * Invariants asserted as specs (test names):
 *  - Clean prior turn skips the judge and returns parsed entries unchanged
 *  - Tainted prior turn fires the judge over JSON-serialized entries
 *  - Missing priorCorrelationId short-circuits (no judge call)
 *  - On-disk transcript bytes are byte-identical before and after the read
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const judgeMock = vi.hoisted(() => vi.fn());
vi.mock("../../agents/internal-judge.js", () => ({
  invokeInternalJudge: judgeMock,
}));

import { resetContextTaintStoreQueuesForTests } from "../../security/context-taint-store.js";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
  setExternalContentTouchScope,
} from "../../shared/process-external-content-bodies.js";
import { readTranscriptFileState } from "./transcript-file-state.js";

let tempDir: string;
let sessionFile: string;

async function writeFixtureTranscript(): Promise<void> {
  const lines = [
    JSON.stringify({
      type: "session",
      version: 3,
      id: "session-purify",
      timestamp: "2026-05-31T00:00:00.000Z",
      cwd: tempDir,
    }),
    JSON.stringify({
      type: "message",
      id: "user-1",
      parentId: null,
      timestamp: "2026-05-31T00:00:01.000Z",
      message: { role: "user", content: "untrusted body in transcript" },
    }),
    JSON.stringify({
      type: "message",
      id: "assistant-1",
      parentId: "user-1",
      timestamp: "2026-05-31T00:00:02.000Z",
      message: { role: "assistant", content: [{ type: "text", text: "reply" }] },
    }),
  ];
  await fs.writeFile(sessionFile, `${lines.join("\n")}\n`, "utf8");
}

function markPriorTurnTainted(correlationId: string): void {
  setExternalContentTouchScope(correlationId);
  recordExternalContentBody("untrusted-content-body-long-enough-to-taint");
  setExternalContentTouchScope(undefined);
}

beforeEach(async () => {
  judgeMock.mockReset();
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-pi-purify-"));
  sessionFile = path.join(tempDir, "session.jsonl");
  await writeFixtureTranscript();
});

afterEach(async () => {
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("readTranscriptFileState — purification opt-in", () => {
  it("skips the judge when prior turn was clean", async () => {
    const before = await fs.readFile(sessionFile, "utf8");
    const state = await readTranscriptFileState(sessionFile, {
      priorCorrelationId: "corr-clean",
      sessionId: "session-purify",
    });
    expect(judgeMock).not.toHaveBeenCalled();
    expect(state.entries.length).toBeGreaterThan(0);
    const after = await fs.readFile(sessionFile, "utf8");
    expect(after).toBe(before);
  });

  it("fires the judge when prior turn touched untrusted content", async () => {
    markPriorTurnTainted("corr-tainted");
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: [], removed: ["untrusted-content-body-long-enough-to-taint"] },
      modelId: "claude-haiku-4-5",
    });
    const before = await fs.readFile(sessionFile, "utf8");
    await readTranscriptFileState(sessionFile, {
      priorCorrelationId: "corr-tainted",
      sessionId: "session-purify",
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    const after = await fs.readFile(sessionFile, "utf8");
    expect(after).toBe(before);
  });

  it("short-circuits when priorCorrelationId is omitted", async () => {
    markPriorTurnTainted("corr-tainted-but-unconsulted");
    const state = await readTranscriptFileState(sessionFile);
    expect(judgeMock).not.toHaveBeenCalled();
    expect(state.entries.length).toBeGreaterThan(0);
  });

  it("preserves on-disk bytes across the purified read", async () => {
    markPriorTurnTainted("corr-disk-check");
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: [], removed: ["untrusted-content-body-long-enough-to-taint"] },
      modelId: "claude-haiku-4-5",
    });
    const before = await fs.readFile(sessionFile, "utf8");
    await readTranscriptFileState(sessionFile, {
      priorCorrelationId: "corr-disk-check",
      sessionId: "session-purify",
    });
    const after = await fs.readFile(sessionFile, "utf8");
    expect(after).toBe(before);
  });
});

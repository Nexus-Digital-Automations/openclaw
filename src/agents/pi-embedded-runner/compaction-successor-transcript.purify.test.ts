/**
 * Owner: agents/pi-embedded-runner/compaction-successor-transcript.purify.test
 *
 * Spec: D.3 part 3 — rotateTranscriptFileAfterCompaction forwards
 * priorCorrelationId + sessionId into readTranscriptFileState so the
 * post-parse entries route through the purifier before the compaction
 * successor builder reads them. The on-disk transcript is not rewritten.
 *
 * Invariants asserted as specs (test names):
 *  - Clean prior turn does not invoke the judge during rotation
 *  - Tainted prior turn triggers the judge before the rotation runs
 *  - Omitting purification context preserves prior pre-D.3 behavior
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
import { rotateTranscriptFileAfterCompaction } from "./compaction-successor-transcript.js";

let tempDir: string;
let sessionFile: string;

async function writeFixtureTranscript(): Promise<void> {
  const lines = [
    JSON.stringify({
      type: "session",
      version: 3,
      id: "session-purify-compact",
      timestamp: "2026-05-31T00:00:00.000Z",
      cwd: tempDir,
    }),
    JSON.stringify({
      type: "message",
      id: "user-1",
      parentId: null,
      timestamp: "2026-05-31T00:00:01.000Z",
      message: { role: "user", content: "untrusted body kept across rotation" },
    }),
    JSON.stringify({
      type: "message",
      id: "assistant-1",
      parentId: "user-1",
      timestamp: "2026-05-31T00:00:02.000Z",
      message: { role: "assistant", content: [{ type: "text", text: "ok" }] },
    }),
  ];
  await fs.writeFile(sessionFile, `${lines.join("\n")}\n`, "utf8");
}

function markPriorTurnTainted(correlationId: string): void {
  setExternalContentTouchScope(correlationId);
  recordExternalContentBody("compaction-untrusted-body-long-enough-to-taint");
  setExternalContentTouchScope(undefined);
}

beforeEach(async () => {
  judgeMock.mockReset();
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-pi-compact-purify-"));
  sessionFile = path.join(tempDir, "session.jsonl");
  await writeFixtureTranscript();
});

afterEach(async () => {
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("rotateTranscriptFileAfterCompaction — purification forwarding", () => {
  it("skips the judge when prior turn was clean", async () => {
    const before = await fs.readFile(sessionFile, "utf8");
    await rotateTranscriptFileAfterCompaction({
      sessionFile,
      priorCorrelationId: "corr-clean-compact",
      sessionId: "session-purify-compact",
    });
    expect(judgeMock).not.toHaveBeenCalled();
    const after = await fs.readFile(sessionFile, "utf8");
    expect(after).toBe(before);
  });

  it("invokes the judge when prior turn touched untrusted content", async () => {
    markPriorTurnTainted("corr-tainted-compact");
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: [], removed: ["compaction-untrusted-body-long-enough-to-taint"] },
      modelId: "claude-haiku-4-5",
    });
    const before = await fs.readFile(sessionFile, "utf8");
    await rotateTranscriptFileAfterCompaction({
      sessionFile,
      priorCorrelationId: "corr-tainted-compact",
      sessionId: "session-purify-compact",
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    const after = await fs.readFile(sessionFile, "utf8");
    expect(after).toBe(before);
  });

  it("preserves pre-D.3 behavior when purification context is omitted", async () => {
    markPriorTurnTainted("corr-not-consulted");
    await rotateTranscriptFileAfterCompaction({ sessionFile });
    expect(judgeMock).not.toHaveBeenCalled();
  });
});

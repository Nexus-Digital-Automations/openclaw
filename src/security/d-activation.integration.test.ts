/**
 * Owner: security/d-activation.integration.test
 *
 * Spec: D-activation — end-to-end chain proving that the producer
 * (D.5 turn-start scope + body record), persistence (D.6 markCorrelationTainted +
 * setPriorRunCorrelationId), and consumer (D.7 priorCorrelationId on the
 * transcript read) cooperate so the purifier fires on the next turn when
 * the prior turn touched untrusted content.
 *
 * Test mocks the judge so the assertion is "judge was invoked once when
 * the prior turn was tainted, never when the prior turn was clean".
 *
 * Invariants asserted as specs (test names):
 *  - Clean prior turn does NOT trigger the next turn's purifier
 *  - Tainted prior turn (in-process signal) DOES trigger the next turn's
 *    purifier when the consumer threads getPriorRunCorrelationId
 *  - markCorrelationTainted writes to disk so cross-restart paths can
 *    answer wasCorrelationTainted after the in-process registry is
 *    cleared (parallel to a process restart)
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const judgeMock = vi.hoisted(() => vi.fn());
vi.mock("../agents/internal-judge.js", () => ({
  invokeInternalJudge: judgeMock,
}));

import {
  clearPriorRunCorrelationIdsForTests,
  getPriorRunCorrelationId,
  setPriorRunCorrelationId,
} from "../agents/pi-embedded-runner/run-state.js";
import {
  clearExternalContentBodiesForTests,
  didCorrelationTouchExternalContent,
  recordExternalContentBody,
  setExternalContentTouchScope,
} from "../shared/process-external-content-bodies.js";
import { purifyParsedTranscriptEntries } from "./context-purification.js";
import {
  markCorrelationTainted,
  resetContextTaintStoreQueuesForTests,
  wasCorrelationTainted,
} from "./context-taint-store.js";

let tempDir: string;
let taintStorePath: string;

function simulateProducerSide(runId: string, sessionId: string, untrustedBody: string): void {
  setExternalContentTouchScope(runId);
  recordExternalContentBody(untrustedBody);
  setExternalContentTouchScope(undefined);
  setPriorRunCorrelationId(sessionId, runId);
}

async function simulatePersistenceSide(runId: string): Promise<void> {
  if (didCorrelationTouchExternalContent(runId)) {
    await markCorrelationTainted(runId, { storePath: taintStorePath });
  }
}

beforeEach(async () => {
  judgeMock.mockReset();
  clearExternalContentBodiesForTests();
  clearPriorRunCorrelationIdsForTests();
  resetContextTaintStoreQueuesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-d-activation-"));
  taintStorePath = path.join(tempDir, "context-taint.ndjson");
});

afterEach(async () => {
  clearExternalContentBodiesForTests();
  clearPriorRunCorrelationIdsForTests();
  resetContextTaintStoreQueuesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("D-activation — clean prior turn", () => {
  it("does not invoke the judge on the next turn", async () => {
    const sessionId = "session-clean";
    setPriorRunCorrelationId(sessionId, "corr-clean");
    const priorId = getPriorRunCorrelationId(sessionId);
    expect(priorId).toBe("corr-clean");
    const verdict = await purifyParsedTranscriptEntries({
      entries: [{ id: "x", text: "any" }],
      priorCorrelationId: priorId!,
      getContent: (entry) => entry.text,
      setContent: (entry, text) => ({ ...entry, text }),
      taintStorePath,
    });
    expect(judgeMock).not.toHaveBeenCalled();
    expect(verdict.purified).toBe(false);
  });
});

describe("D-activation — tainted prior turn fires the consumer", () => {
  it("activates the purifier when the producer marked the turn", async () => {
    const sessionId = "session-tainted";
    const runId = "corr-tainted";
    simulateProducerSide(runId, sessionId, "untrusted-body-long-enough-to-taint");
    await simulatePersistenceSide(runId);
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["clean"], removed: ["untrusted-body-long-enough-to-taint"] },
      modelId: "claude-haiku-4-5",
    });
    const priorId = getPriorRunCorrelationId(sessionId);
    expect(priorId).toBe(runId);
    const verdict = await purifyParsedTranscriptEntries({
      entries: [{ id: "x", text: "untrusted message body" }],
      priorCorrelationId: priorId!,
      getContent: (entry) => entry.text,
      setContent: (entry, text) => ({ ...entry, text }),
      taintStorePath,
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    expect(verdict.purified).toBe(true);
  });
});

describe("D-activation — cross-restart proof via disk taint store", () => {
  it("answers wasCorrelationTainted after in-process state is wiped", async () => {
    const runId = "corr-survives-restart";
    setExternalContentTouchScope(runId);
    recordExternalContentBody("untrusted-cross-restart-body-long-enough-to-taint");
    setExternalContentTouchScope(undefined);
    await markCorrelationTainted(runId, { storePath: taintStorePath });
    // Simulate a process restart by clearing the in-process body registry.
    clearExternalContentBodiesForTests();
    expect(didCorrelationTouchExternalContent(runId)).toBe(false);
    expect(await wasCorrelationTainted(runId, { storePath: taintStorePath })).toBe(true);
  });
});

/**
 * Owner: security/context-purification.parse-post-hook.test
 *
 * Spec: D.2 — purifyParsedTranscriptEntries is the next-turn context-load
 * filter. It consults BOTH the in-process touched signal (process-global)
 * AND the disk taint store (cross-restart), then on touch invokes
 * purifyTranscript over the concatenated entry content and returns
 * entries with sanitized content.
 *
 * Invariants:
 *  - Clean turn (neither signal set) → entries returned byte-identical
 *  - In-process signal set → purifier fires
 *  - Disk store says tainted → purifier fires (cross-restart path)
 *  - Judge approves → entries get sanitized content by index
 *  - Judge errors → entries returned byte-identical (fail-open)
 *  - Empty entries → no judge call
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
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
  setExternalContentTouchScope,
} from "../shared/process-external-content-bodies.js";
import { purifyParsedTranscriptEntries } from "./context-purification.js";
import {
  markCorrelationTainted,
  resetContextTaintStoreQueuesForTests,
} from "./context-taint-store.js";

type FakeEntry = { id: string; text: string };

const getContent = (entry: FakeEntry): string => entry.text;
const setContent = (entry: FakeEntry, text: string): FakeEntry => ({ ...entry, text });

let tempDir: string;

beforeEach(async () => {
  judgeMock.mockReset();
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-purify-d2-"));
  // Point the taint-store env path at a temp file so tests cannot pollute
  // the real logs/context-taint.ndjson. The taint-store reads
  // opts.storePath when provided; production callers will use the default
  // path, but tests do not have that override available here, so we
  // intentionally avoid the disk-tainted branch unless the test
  // explicitly seeds it via markCorrelationTainted({storePath}).
  // NOTE: purifyParsedTranscriptEntries reads from the DEFAULT path; to
  // unit-test the cross-restart branch, the wrapper would need a storePath
  // injection point. For D.2 we cover that branch via the in-process flag
  // and add a focused cross-restart test once D.3 wires the consumer with
  // a configurable path.
});

afterEach(async () => {
  clearExternalContentBodiesForTests();
  resetContextTaintStoreQueuesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

function entries(): FakeEntry[] {
  return [
    { id: "a", text: "first message" },
    { id: "b", text: "second message" },
  ];
}

describe("purifyParsedTranscriptEntries — clean turn skips judge", () => {
  it("returns entries byte-identical when no signal is set", async () => {
    const input = entries();
    const result = await purifyParsedTranscriptEntries({
      entries: input,
      priorCorrelationId: "corr-clean",
      getContent,
      setContent,
    });
    expect(judgeMock).not.toHaveBeenCalled();
    expect(result.purified).toBe(false);
    expect(result.entries).toEqual(input);
    if (!result.purified) {
      expect(result.reason).toBe("clean_turn");
    }
  });

  it("returns empty-entries reason when input is empty (no judge call)", async () => {
    setExternalContentTouchScope("corr-touched-but-empty");
    recordExternalContentBody("untrusted snippet long enough to taint");
    setExternalContentTouchScope(undefined);
    const result = await purifyParsedTranscriptEntries({
      entries: [],
      priorCorrelationId: "corr-touched-but-empty",
      getContent,
      setContent,
    });
    expect(judgeMock).not.toHaveBeenCalled();
    expect(result.purified).toBe(false);
    if (!result.purified) {
      expect(result.reason).toBe("empty_entries");
    }
  });
});

describe("purifyParsedTranscriptEntries — in-process touch signal fires purifier", () => {
  it("invokes judge and rewrites entry content with sanitized lines on approval", async () => {
    setExternalContentTouchScope("corr-touched");
    recordExternalContentBody("untrusted snippet long enough to taint the registry");
    setExternalContentTouchScope(undefined);
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["clean first", "clean second"], removed: ["injection: ignore prior"] },
      modelId: "claude-haiku-4-5",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 20,
    });
    const input = entries();
    const result = await purifyParsedTranscriptEntries({
      entries: input,
      priorCorrelationId: "corr-touched",
      getContent,
      setContent,
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    expect(result.purified).toBe(true);
    if (result.purified) {
      expect(result.entries.map((entry) => entry.text)).toEqual(["clean first", "clean second"]);
      expect(result.entries.map((entry) => entry.id)).toEqual(["a", "b"]);
      expect(result.removedCount).toBe(1);
    }
  });

  it("returns entries unchanged when judge fails (fail-open)", async () => {
    setExternalContentTouchScope("corr-touched-but-fail");
    recordExternalContentBody("untrusted snippet long enough to taint the registry");
    setExternalContentTouchScope(undefined);
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "timeout", detail: "30s" });
    const input = entries();
    const result = await purifyParsedTranscriptEntries({
      entries: input,
      priorCorrelationId: "corr-touched-but-fail",
      getContent,
      setContent,
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    expect(result.purified).toBe(false);
    expect(result.entries).toEqual(input);
    if (!result.purified) {
      expect(result.reason).toBe("judge_unavailable:timeout");
    }
  });

  it("drops entries beyond what the judge returned (conservative truncation)", async () => {
    setExternalContentTouchScope("corr-touched-short");
    recordExternalContentBody("untrusted snippet long enough to taint the registry");
    setExternalContentTouchScope(undefined);
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["only first"], removed: [] },
      modelId: "claude-haiku-4-5",
      latencyMs: 80,
      inputTokens: 40,
      outputTokens: 10,
    });
    const result = await purifyParsedTranscriptEntries({
      entries: entries(),
      priorCorrelationId: "corr-touched-short",
      getContent,
      setContent,
    });
    if (!result.purified) {
      throw new Error("expected purified");
    }
    expect(result.entries.map((entry) => entry.text)).toEqual(["only first", ""]);
  });
});

describe("purifyParsedTranscriptEntries — disk taint store cross-restart path", () => {
  it("fires the purifier when the disk store says the prior correlation was tainted", async () => {
    const storePath = path.join(tempDir, "context-taint.ndjson");
    await markCorrelationTainted("corr-disk-tainted", { storePath });
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["sanitized one", "sanitized two"], removed: [] },
      modelId: "claude-haiku-4-5",
      latencyMs: 90,
      inputTokens: 45,
      outputTokens: 15,
    });
    const result = await purifyParsedTranscriptEntries({
      entries: entries(),
      priorCorrelationId: "corr-disk-tainted",
      getContent,
      setContent,
      taintStorePath: storePath,
    });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    expect(result.purified).toBe(true);
    if (result.purified) {
      expect(result.entries.map((entry) => entry.text)).toEqual(["sanitized one", "sanitized two"]);
    }
  });

  it("does not fire when neither the in-process flag nor the disk store is set", async () => {
    const storePath = path.join(tempDir, "context-taint-clean.ndjson");
    const result = await purifyParsedTranscriptEntries({
      entries: entries(),
      priorCorrelationId: "corr-never-seen",
      getContent,
      setContent,
      taintStorePath: storePath,
    });
    expect(judgeMock).not.toHaveBeenCalled();
    expect(result.purified).toBe(false);
  });
});

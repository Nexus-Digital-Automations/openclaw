/**
 * Owner: agents/pi-embedded-runner/run-state.prior-correlation.test
 *
 * Spec: D-0 — per-session previous-turn correlationId registry. The
 * D-activation pipeline writes this at turn-end (D.6) and reads it at
 * the start of the next turn's context-load (D.7) so the purifier knows
 * whether the prior turn touched untrusted content.
 *
 * Invariants asserted as specs (test names):
 *  - Get on empty registry returns undefined
 *  - Set + get round-trip preserves the correlationId
 *  - Empty/missing sessionId is a silent no-op (no map pollution)
 *  - Empty/missing correlationId is a silent no-op
 *  - clearForTests wipes the registry
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  clearPriorRunCorrelationIdsForTests,
  getPriorRunCorrelationId,
  setPriorRunCorrelationId,
} from "./run-state.js";

afterEach(() => {
  clearPriorRunCorrelationIdsForTests();
});

describe("priorRunCorrelationId registry", () => {
  it("returns undefined for an unknown sessionId", () => {
    expect(getPriorRunCorrelationId("session-unknown")).toBeUndefined();
  });

  it("round-trips a sessionId → correlationId mapping", () => {
    setPriorRunCorrelationId("session-1", "corr-abc");
    expect(getPriorRunCorrelationId("session-1")).toBe("corr-abc");
  });

  it("overwrites the value when set is called twice", () => {
    setPriorRunCorrelationId("session-1", "corr-first");
    setPriorRunCorrelationId("session-1", "corr-second");
    expect(getPriorRunCorrelationId("session-1")).toBe("corr-second");
  });

  it("isolates entries by sessionId", () => {
    setPriorRunCorrelationId("session-a", "corr-a");
    setPriorRunCorrelationId("session-b", "corr-b");
    expect(getPriorRunCorrelationId("session-a")).toBe("corr-a");
    expect(getPriorRunCorrelationId("session-b")).toBe("corr-b");
  });

  it("ignores empty sessionId on set", () => {
    setPriorRunCorrelationId("", "corr-orphan");
    expect(getPriorRunCorrelationId("")).toBeUndefined();
  });

  it("ignores empty correlationId on set", () => {
    setPriorRunCorrelationId("session-1", "");
    expect(getPriorRunCorrelationId("session-1")).toBeUndefined();
  });

  it("returns undefined for empty sessionId on get", () => {
    setPriorRunCorrelationId("session-1", "corr-real");
    expect(getPriorRunCorrelationId("")).toBeUndefined();
  });

  it("clearForTests wipes the registry", () => {
    setPriorRunCorrelationId("session-1", "corr-keep");
    clearPriorRunCorrelationIdsForTests();
    expect(getPriorRunCorrelationId("session-1")).toBeUndefined();
  });
});

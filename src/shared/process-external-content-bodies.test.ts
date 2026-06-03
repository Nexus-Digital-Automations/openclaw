import { afterEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  didCorrelationTouchExternalContent,
  findArgvExternalContentTaint,
  recordExternalContentBody,
  scanArgvForExternalContent,
  setExternalContentTouchScope,
} from "./process-external-content-bodies.js";

afterEach(() => {
  clearExternalContentBodiesForTests();
});

describe("process-external-content-bodies registry", () => {
  it("finds a recorded body when it appears as a substring of any argv element", () => {
    const body = "this came from a webhook payload";
    recordExternalContentBody(body);
    const hit = findArgvExternalContentTaint(["git", "commit", "-m", `note: ${body}`]);
    expect(hit).toBe(body);
  });

  it("returns undefined when argv carries only benign tokens", () => {
    recordExternalContentBody("hostile payload from webhook");
    expect(findArgvExternalContentTaint(["git", "status"])).toBeUndefined();
  });

  it("ignores short bodies so common phrases do not force approval", () => {
    recordExternalContentBody("short");
    expect(findArgvExternalContentTaint(["echo", "short text"])).toBeUndefined();
  });

  it("returns undefined when the argv element itself is shorter than the floor", () => {
    recordExternalContentBody("a body long enough to be tainted");
    expect(findArgvExternalContentTaint(["t", "x"])).toBeUndefined();
  });
});

describe("scanArgvForExternalContent (structured params)", () => {
  // Regression: JSON.stringify escaped newlines/quotes/backslashes, so a tainted
  // body containing them would not substring-match and silently bypass the gate.
  it("detects a tainted body with newlines/quotes/backslashes in an object field", () => {
    const body = 'EXTERNAL\nblock "with" quotes and a \\ backslash — long enough to taint';
    recordExternalContentBody(body);
    const hits = scanArgvForExternalContent({
      file_path: "/tmp/out.txt",
      content: `prefix ${body} suffix`,
    });
    expect(hits).toContain(body);
  });

  it("walks nested object/array structures to leaf strings", () => {
    const body = "nested webhook body that is long enough to taint";
    recordExternalContentBody(body);
    const hits = scanArgvForExternalContent({ patch: { files: [{ add: body }] } });
    expect(hits).toContain(body);
  });

  it("returns no match for benign structured params", () => {
    recordExternalContentBody("a hostile external body long enough to taint");
    expect(scanArgvForExternalContent({ file_path: "/tmp/notes.md", content: "ok" })).toEqual([]);
  });
});

describe("per-correlation-id touch scope (D.1)", () => {
  it("flags the active correlation when a body is recorded inside its scope", () => {
    setExternalContentTouchScope("corr-touched");
    recordExternalContentBody("untrusted snippet from webhook payload");
    setExternalContentTouchScope(undefined);
    expect(didCorrelationTouchExternalContent("corr-touched")).toBe(true);
  });

  it("does not flag correlations whose scope was never active during a record", () => {
    setExternalContentTouchScope("corr-active");
    recordExternalContentBody("untrusted snippet from webhook payload");
    setExternalContentTouchScope(undefined);
    expect(didCorrelationTouchExternalContent("corr-other")).toBe(false);
  });

  it("ignores records that occur outside any active scope (no flag)", () => {
    recordExternalContentBody("untrusted snippet from webhook payload");
    expect(didCorrelationTouchExternalContent("corr-x")).toBe(false);
  });

  it("does not flag the scope when only short-floor records are attempted", () => {
    setExternalContentTouchScope("corr-clean");
    recordExternalContentBody("short");
    setExternalContentTouchScope(undefined);
    expect(didCorrelationTouchExternalContent("corr-clean")).toBe(false);
  });

  // L2: concurrent runs must not clobber each other's scope. A module-global
  // pointer would attribute run A's recorded body to run B after interleaving.
  it("isolates touch scope across concurrent runs", async () => {
    async function runTurn(id: string, body: string): Promise<void> {
      setExternalContentTouchScope(id);
      await Promise.resolve(); // yield so the other run interleaves
      recordExternalContentBody(body);
    }
    await Promise.all([
      runTurn("run-a", "untrusted body from run A long enough to taint"),
      runTurn("run-b", "untrusted body from run B long enough to taint"),
    ]);
    expect(didCorrelationTouchExternalContent("run-a")).toBe(true);
    expect(didCorrelationTouchExternalContent("run-b")).toBe(true);
  });

  it("returns false for empty correlation id", () => {
    expect(didCorrelationTouchExternalContent("")).toBe(false);
  });
});

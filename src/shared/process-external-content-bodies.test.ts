import { afterEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  findArgvExternalContentTaint,
  recordExternalContentBody,
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

/**
 * Owner: security/tool-output-redactor.
 *
 * Spec: inbound symmetric counterpart to the output firewall. The redactor
 * scans every string field in a tool's execution payload (stdout, stderr,
 * structured result, recursive arrays/objects) and replaces echoes of
 * registered secrets/canaries/external-content bodies with family-tagged
 * placeholders before the result is fed back into the model context.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
} from "../shared/process-external-content-bodies.js";
import {
  clearResolvedSecretsForTests,
  recordResolvedSecret,
} from "../shared/process-secret-literals.js";
import { createToolOutputRedactor } from "./tool-output-redactor.js";

beforeEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

afterEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

describe("createToolOutputRedactor — secret family", () => {
  it("redacts a registered secret echoed in a stdout string", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({
      stdout: "leaked key sk-not-a-real-format-deadbeef in shell output",
    });
    expect(result).toEqual({
      stdout: "leaked key <redacted:secret> in shell output",
    });
  });

  it("redacts a secret nested inside a structured result object", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({
      ok: true,
      result: {
        items: [
          { id: 1, body: "value sk-not-a-real-format-deadbeef trailing" },
          { id: 2, body: "clean" },
        ],
      },
    });
    expect(result).toEqual({
      ok: true,
      result: {
        items: [
          { id: 1, body: "value <redacted:secret> trailing" },
          { id: 2, body: "clean" },
        ],
      },
    });
  });
});

describe("createToolOutputRedactor — canary family", () => {
  it("redacts an external-content canary literal echoed in stdout", () => {
    const canary = "OPENCLAW_CANARY_abcdef0123456789";
    recordExternalContentBody(canary);
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({
      stdout: `tool echoed ${canary} back into output`,
    });
    expect(result).toEqual({
      stdout: "tool echoed <redacted:canary> back into output",
    });
  });
});

describe("createToolOutputRedactor — passthrough behaviour", () => {
  it("returns the payload unchanged when every registry is empty", () => {
    const redactor = createToolOutputRedactor();
    const payload = {
      ok: true,
      stdout: "nothing sensitive here",
      stderr: "",
      result: { count: 3, items: ["a", "b", "c"] },
    };
    expect(redactor.redact(payload)).toEqual(payload);
  });

  it("does not redact sub-floor literals (false-positive prevention)", () => {
    recordResolvedSecret("short"); // 5 chars < 8-char floor
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({ stdout: "this short value stays" });
    expect(result).toEqual({ stdout: "this short value stays" });
  });

  it("never rewrites object keys, only values", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({
      "sk-not-a-real-format-deadbeef": "value-not-sensitive",
    });
    expect(result).toEqual({
      "sk-not-a-real-format-deadbeef": "value-not-sensitive",
    });
  });
});

describe("createToolOutputRedactor — multi-family", () => {
  it("masks a secret and a canary in the same stdout with their own family tags", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const canary = "OPENCLAW_CANARY_abcdef0123456789";
    recordExternalContentBody(canary);
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({
      stdout: `key=sk-not-a-real-format-deadbeef canary=${canary} end`,
    });
    expect(result).toEqual({
      stdout: "key=<redacted:secret> canary=<redacted:canary> end",
    });
  });

  it("masks an external-content marker body with the external-content tag", () => {
    const body = "this is a webhook payload reaching the gateway";
    recordExternalContentBody(body);
    const redactor = createToolOutputRedactor();
    const result = redactor.redact({ stderr: `tool said: ${body} okay` });
    expect(result).toEqual({
      stderr: "tool said: <redacted:external-content> okay",
    });
  });
});

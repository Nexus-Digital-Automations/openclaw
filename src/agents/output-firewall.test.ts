import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
} from "../shared/process-external-content-bodies.js";
import {
  clearResolvedSecretsForTests,
  recordResolvedSecret,
} from "../shared/process-secret-literals.js";
import { createOutputFirewallState, scanOutputChunk } from "./output-firewall.js";

beforeEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

afterEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

describe("scanOutputChunk", () => {
  it("passes through model output that contains no known literals", () => {
    const state = createOutputFirewallState();
    const verdict = scanOutputChunk("hello, this is normal model output", state);
    expect(verdict.kind).toBe("pass");
    expect(verdict.sanitized).toBe("hello, this is normal model output");
  });

  it("blocks output that contains a recorded resolved secret and reports the match", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const state = createOutputFirewallState();
    const verdict = scanOutputChunk("here is the key sk-not-a-real-format-deadbeef value", state);
    expect(verdict.kind).toBe("block");
    if (verdict.kind === "block") {
      expect(verdict.matched).toBe("sk-not-a-real-format-deadbeef");
      expect(verdict.sanitized).toContain("«REDACTED»");
      expect(verdict.sanitized).not.toContain("sk-not-a-real-format-deadbeef");
    }
  });

  it("blocks output that contains a recorded external-content body", () => {
    const body = "this is a webhook payload reaching the gateway";
    recordExternalContentBody(body);
    const state = createOutputFirewallState();
    const verdict = scanOutputChunk(`assistant said: ${body}`, state);
    expect(verdict.kind).toBe("block");
  });

  it("catches a literal that straddles two chunks by carrying the tail forward", () => {
    recordResolvedSecret("sk-cross-chunk-token-aaaa");
    const state1 = createOutputFirewallState();
    const verdict1 = scanOutputChunk("prefix sk-cross-chunk", state1);
    expect(verdict1.kind).toBe("pass");
    const verdict2 = scanOutputChunk("-token-aaaa suffix", verdict1.nextState);
    expect(verdict2.kind).toBe("block");
  });

  it("ignores short literals so common substrings do not block normal output", () => {
    recordResolvedSecret("abc");
    const state = createOutputFirewallState();
    const verdict = scanOutputChunk("the alphabet starts with abc and continues", state);
    expect(verdict.kind).toBe("pass");
  });

  it("never trims the carry below the longest literal length minus one", () => {
    recordResolvedSecret("xxxxxxxxxxxxxxxxxxxx");
    const state = createOutputFirewallState();
    const verdict = scanOutputChunk("padding padding padding", state);
    expect(verdict.kind).toBe("pass");
    expect(verdict.nextState.carry.length).toBe(19);
  });
});

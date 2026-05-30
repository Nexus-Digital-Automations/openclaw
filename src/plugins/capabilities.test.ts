/**
 * Spec: G.1 plugin capability manifest — typed allowlists + runtime
 * check helpers + manifest normalization.
 */
import { describe, expect, it } from "vitest";
import {
  checkFsScope,
  checkHookCapability,
  checkHttpAllowlist,
  normalizeCapabilitiesManifest,
  type PluginCapabilities,
} from "./capabilities.js";

describe("checkHookCapability", () => {
  it("approves a declared hook", () => {
    const capabilities: PluginCapabilities = { hooks: ["before_tool_call"] };
    expect(checkHookCapability(capabilities, "before_tool_call")).toEqual({ ok: true });
  });

  it("rejects an undeclared hook with a precise reason", () => {
    const capabilities: PluginCapabilities = { hooks: ["before_tool_call"] };
    const verdict = checkHookCapability(capabilities, "session_start");
    expect(verdict.ok).toBe(false);
    if (verdict.ok) {
      return;
    }
    expect(verdict.category).toBe("hooks");
    expect(verdict.reason).toContain("session_start");
  });

  it("rejects every hook when manifest is undefined", () => {
    expect(checkHookCapability(undefined, "before_tool_call").ok).toBe(false);
  });

  it("rejects every hook when hooks list is empty", () => {
    expect(checkHookCapability({ hooks: [] }, "before_tool_call").ok).toBe(false);
  });
});

describe("checkHttpAllowlist", () => {
  it("approves a declared host", () => {
    const capabilities: PluginCapabilities = { httpAllowlist: ["api.example.com"] };
    expect(checkHttpAllowlist(capabilities, "api.example.com")).toEqual({ ok: true });
  });

  it("rejects an undeclared host so silent passthrough cannot happen", () => {
    const capabilities: PluginCapabilities = { httpAllowlist: ["api.example.com"] };
    expect(checkHttpAllowlist(capabilities, "evil.example.org").ok).toBe(false);
  });

  it("rejects when manifest has no httpAllowlist (deny-by-default)", () => {
    expect(checkHttpAllowlist({}, "api.example.com").ok).toBe(false);
    expect(checkHttpAllowlist(undefined, "api.example.com").ok).toBe(false);
  });

  it("rejects empty host strings", () => {
    expect(
      checkHttpAllowlist({ httpAllowlist: ["api.example.com"] }, "").ok,
    ).toBe(false);
  });
});

describe("checkFsScope", () => {
  it("approves a declared scope", () => {
    expect(checkFsScope({ fsScopes: ["workspace.read"] }, "workspace.read")).toEqual({ ok: true });
  });

  it("rejects an undeclared scope", () => {
    expect(checkFsScope({ fsScopes: ["workspace.read"] }, "workspace.write").ok).toBe(false);
  });

  it("rejects when manifest has no fsScopes", () => {
    expect(checkFsScope({}, "workspace.read").ok).toBe(false);
  });
});

describe("normalizeCapabilitiesManifest", () => {
  it("returns null for non-object input", () => {
    expect(normalizeCapabilitiesManifest(null)).toBeNull();
    expect(normalizeCapabilitiesManifest(undefined)).toBeNull();
    expect(normalizeCapabilitiesManifest("nope")).toBeNull();
    expect(normalizeCapabilitiesManifest(123)).toBeNull();
  });

  it("filters out unknown hook names", () => {
    const result = normalizeCapabilitiesManifest({
      hooks: ["before_tool_call", "not_a_real_hook"],
    });
    expect(result?.hooks).toEqual(["before_tool_call"]);
  });

  it("filters out unknown fs scopes", () => {
    const result = normalizeCapabilitiesManifest({
      fsScopes: ["workspace.read", "system.write"],
    });
    expect(result?.fsScopes).toEqual(["workspace.read"]);
  });

  it("filters non-string entries out of every array", () => {
    const result = normalizeCapabilitiesManifest({
      hooks: ["before_tool_call", 42, null],
      httpAllowlist: ["api.example.com", { obj: true }],
    });
    expect(result?.hooks).toEqual(["before_tool_call"]);
    expect(result?.httpAllowlist).toEqual(["api.example.com"]);
  });

  it("returns an empty object for an empty record", () => {
    expect(normalizeCapabilitiesManifest({})).toEqual({});
  });

  it("preserves all categories when present", () => {
    const result = normalizeCapabilitiesManifest({
      hooks: ["before_tool_call"],
      providers: ["myprovider"],
      tools: ["mytool"],
      channels: ["mychan"],
      httpAllowlist: ["api.example.com"],
      fsScopes: ["workspace.read"],
    });
    expect(result).toEqual({
      hooks: ["before_tool_call"],
      providers: ["myprovider"],
      tools: ["mytool"],
      channels: ["mychan"],
      httpAllowlist: ["api.example.com"],
      fsScopes: ["workspace.read"],
    });
  });
});

describe("denial categories — composition guard", () => {
  it("category field lets call-site logging distinguish refusal kinds", () => {
    const hookFail = checkHookCapability({}, "before_tool_call");
    const httpFail = checkHttpAllowlist({}, "api.example.com");
    const fsFail = checkFsScope({}, "workspace.read");
    if (hookFail.ok || httpFail.ok || fsFail.ok) {
      throw new Error("expected all denials");
    }
    expect(hookFail.category).toBe("hooks");
    expect(httpFail.category).toBe("httpAllowlist");
    expect(fsFail.category).toBe("fsScopes");
  });
});

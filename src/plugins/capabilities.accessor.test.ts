/**
 * Owner: plugins/capabilities.accessor.test
 *
 * Spec: C.2 — runtime capability accessor populated by the install gate
 * and consumed by the warn-mode hook gate (C.3) + HTTP/FS guards (E).
 *
 * Invariants:
 *  - set + get round-trip with the same id returns the cached shape
 *  - get for an unknown id returns undefined (not empty object)
 *  - empty plugin id is a no-op for both directions
 *  - re-set with the same id overwrites (matches plugin upgrade behavior)
 *  - clear wipes the cache (test-only escape hatch)
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearPluginCapabilitiesForTests,
  getPluginCapabilities,
  setPluginCapabilities,
} from "./capabilities.js";

beforeEach(() => {
  clearPluginCapabilitiesForTests();
});

afterEach(() => {
  clearPluginCapabilitiesForTests();
});

describe("plugin-capabilities accessor", () => {
  it("returns the cached capabilities for a known plugin id", () => {
    setPluginCapabilities("plugin-alpha", {
      hooks: ["before_tool_call"],
      httpAllowlist: ["api.example.com"],
    });
    const got = getPluginCapabilities("plugin-alpha");
    expect(got?.hooks).toEqual(["before_tool_call"]);
    expect(got?.httpAllowlist).toEqual(["api.example.com"]);
  });

  it("returns undefined for an unknown plugin id (not an empty object)", () => {
    expect(getPluginCapabilities("plugin-never-registered")).toBeUndefined();
  });

  it("ignores empty plugin id on set + read", () => {
    setPluginCapabilities("", { hooks: ["before_tool_call"] });
    expect(getPluginCapabilities("")).toBeUndefined();
  });

  it("overwrites on re-set (matches plugin upgrade behavior)", () => {
    setPluginCapabilities("plugin-beta", { hooks: ["session_start"] });
    setPluginCapabilities("plugin-beta", { hooks: ["session_end"] });
    expect(getPluginCapabilities("plugin-beta")?.hooks).toEqual(["session_end"]);
  });

  it("clearPluginCapabilitiesForTests wipes all registrations", () => {
    setPluginCapabilities("plugin-gamma", { hooks: ["before_tool_call"] });
    clearPluginCapabilitiesForTests();
    expect(getPluginCapabilities("plugin-gamma")).toBeUndefined();
  });
});

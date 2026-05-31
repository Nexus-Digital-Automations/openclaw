/**
 * Owner: plugin-sdk/http-guard-runtime.test
 *
 * Spec: E.1 — pluginFetch bounds plugin-driven HTTP egress to the
 * capability manifest's httpAllowlist.
 *
 * Invariants:
 *  - Plugin with no registered capabilities → throws (no declared
 *    allowlist; refused per the capabilities.ts contract)
 *  - Plugin with empty httpAllowlist → throws
 *  - Allowed host → fetch fires; refused host with same plugin throws
 *  - Both string URL and URL object inputs are honored
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearPluginCapabilitiesForTests, setPluginCapabilities } from "../plugins/capabilities.js";
import { HttpAllowlistDeniedError, pluginFetch } from "./http-guard-runtime.js";

const originalFetch = globalThis.fetch;

beforeEach(() => {
  clearPluginCapabilitiesForTests();
  globalThis.fetch = vi.fn(
    async (_input: string | URL, _init?: RequestInit) => new Response("ok"),
  ) as unknown as typeof globalThis.fetch;
});

afterEach(() => {
  clearPluginCapabilitiesForTests();
  globalThis.fetch = originalFetch;
});

describe("pluginFetch — capability-bounded HTTP egress", () => {
  it("throws HttpAllowlistDeniedError when the plugin has no registered capabilities", async () => {
    await expect(
      pluginFetch({ pluginId: "plugin-no-caps", input: "https://api.example.com/data" }),
    ).rejects.toBeInstanceOf(HttpAllowlistDeniedError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("throws when the plugin's declared httpAllowlist is empty", async () => {
    setPluginCapabilities("plugin-empty-allow", { httpAllowlist: [] });
    await expect(
      pluginFetch({ pluginId: "plugin-empty-allow", input: "https://api.example.com/data" }),
    ).rejects.toBeInstanceOf(HttpAllowlistDeniedError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("allows fetch for hosts listed in the plugin's httpAllowlist", async () => {
    setPluginCapabilities("plugin-allowed", { httpAllowlist: ["api.example.com"] });
    const response = await pluginFetch({
      pluginId: "plugin-allowed",
      input: "https://api.example.com/data",
    });
    expect(await response.text()).toBe("ok");
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("refuses fetch for hosts NOT in the plugin's httpAllowlist", async () => {
    setPluginCapabilities("plugin-allowed", { httpAllowlist: ["api.example.com"] });
    await expect(
      pluginFetch({ pluginId: "plugin-allowed", input: "https://evil.example/data" }),
    ).rejects.toBeInstanceOf(HttpAllowlistDeniedError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("attaches pluginId + host + reason to the thrown error for forensic logging", async () => {
    setPluginCapabilities("plugin-strict", { httpAllowlist: ["api.example.com"] });
    try {
      await pluginFetch({ pluginId: "plugin-strict", input: "https://forbidden.example/x" });
      expect.unreachable("expected HttpAllowlistDeniedError");
    } catch (err) {
      expect(err).toBeInstanceOf(HttpAllowlistDeniedError);
      if (err instanceof HttpAllowlistDeniedError) {
        expect(err.pluginId).toBe("plugin-strict");
        expect(err.host).toBe("forbidden.example");
        expect(err.reason).toContain("httpAllowlist");
      }
    }
  });

  it("accepts URL object inputs (not just string)", async () => {
    setPluginCapabilities("plugin-allowed", { httpAllowlist: ["api.example.com"] });
    const response = await pluginFetch({
      pluginId: "plugin-allowed",
      input: new URL("https://api.example.com/data"),
    });
    expect(await response.text()).toBe("ok");
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });
});

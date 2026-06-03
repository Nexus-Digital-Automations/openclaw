/**
 * Owner: agents/tools security gate.
 *
 * Spec: capability resolution drives the external-content taint gate, so its
 * precedence (explicit > static > fail-closed) and the dangerous-capability
 * classification are security-critical and must hold exactly.
 */
import { describe, expect, it } from "vitest";
import {
  DANGEROUS_PARAM_KEYS,
  getStaticToolCapabilities,
  isDangerousCapability,
  resolveToolCapabilities,
  type ToolCapability,
} from "./tool-capabilities.js";

describe("tool-capabilities static map", () => {
  it("maps first-party egress/effect tools to dangerous capabilities", () => {
    expect(getStaticToolCapabilities("web_fetch")).toEqual(["egress"]);
    expect(getStaticToolCapabilities("message")).toEqual(["message-send"]);
    expect(getStaticToolCapabilities("gateway")).toEqual(["egress", "control-plane"]);
    expect(getStaticToolCapabilities("exec")).toEqual(["exec"]);
  });

  it("folds aliases via normalizeToolName before lookup", () => {
    expect(getStaticToolCapabilities("bash")).toEqual(["exec"]);
    expect(getStaticToolCapabilities("apply-patch")).toEqual(["write"]);
  });

  it("classifies read as the only non-dangerous (read-local) tool", () => {
    expect(getStaticToolCapabilities("read")).toEqual(["read-local"]);
    expect(isDangerousCapability("read-local")).toBe(false);
  });

  it("returns undefined for unmapped (plugin) tool names", () => {
    expect(getStaticToolCapabilities("some_plugin_tool")).toBeUndefined();
  });
});

describe("isDangerousCapability", () => {
  it("treats every capability except read-local as dangerous", () => {
    const dangerous: ToolCapability[] = [
      "exec",
      "write",
      "edit",
      "egress",
      "message-send",
      "control-plane",
      "delayed-exec",
      "unknown",
    ];
    for (const capability of dangerous) {
      expect(isDangerousCapability(capability), `${capability} must be dangerous`).toBe(true);
    }
    expect(isDangerousCapability("read-local")).toBe(false);
  });
});

describe("resolveToolCapabilities precedence", () => {
  it("prefers an explicit declaration over the static map", () => {
    // A tool whose name would map to egress can still declare read-local.
    expect(resolveToolCapabilities({ name: "web_fetch", capabilities: ["read-local"] })).toEqual([
      "read-local",
    ]);
  });

  it("falls back to the static map when undeclared", () => {
    expect(resolveToolCapabilities({ name: "message" })).toEqual(["message-send"]);
  });

  it("fails closed to unknown for an undeclared, unmapped tool", () => {
    expect(resolveToolCapabilities({ name: "mystery_plugin_tool" })).toEqual(["unknown"]);
  });

  it("ignores an empty declaration and falls through", () => {
    expect(resolveToolCapabilities({ name: "message", capabilities: [] })).toEqual([
      "message-send",
    ]);
    expect(resolveToolCapabilities({ name: "mystery", capabilities: [] })).toEqual(["unknown"]);
  });
});

describe("DANGEROUS_PARAM_KEYS", () => {
  it("makes the whole argv dangerous for exec/write and unknown", () => {
    expect(DANGEROUS_PARAM_KEYS.exec).toBe("*");
    expect(DANGEROUS_PARAM_KEYS.write).toBe("*");
    expect(DANGEROUS_PARAM_KEYS.unknown).toBe("*");
  });

  it("scopes egress and message-send to their sink parameters", () => {
    const egress = DANGEROUS_PARAM_KEYS.egress;
    expect(egress).not.toBe("*");
    expect(egress instanceof Set && egress.has("url")).toBe(true);
    const send = DANGEROUS_PARAM_KEYS["message-send"];
    expect(send instanceof Set && send.has("text")).toBe(true);
  });

  it("leaves read-local with no dangerous parameters", () => {
    const readLocal = DANGEROUS_PARAM_KEYS["read-local"];
    expect(readLocal instanceof Set && readLocal.size === 0).toBe(true);
  });
});

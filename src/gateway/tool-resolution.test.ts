import { beforeAll, describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { DEFAULT_GATEWAY_HTTP_TOOL_DENY } from "../security/dangerous-tools.js";
import { resolveGatewayScopedTools } from "./tool-resolution.js";

describe("resolveGatewayScopedTools", () => {
  beforeAll(() => {
    resolveGatewayScopedTools({
      cfg: { tools: { profile: "minimal" } } as OpenClawConfig,
      sessionKey: "agent:main:telegram:group:-100123",
      messageProvider: "telegram",
      inboundEventKind: "room_event",
      surface: "loopback",
    });
  });

  it("force-allows the message tool for room-event loopback turns", () => {
    const result = resolveGatewayScopedTools({
      cfg: { tools: { profile: "minimal" } } as OpenClawConfig,
      sessionKey: "agent:main:telegram:group:-100123",
      messageProvider: "telegram",
      inboundEventKind: "room_event",
      surface: "loopback",
    });

    const messageTool = result.tools.find((tool) => tool.name === "message");
    expect(messageTool?.description).toContain(
      "visible replies to the current source conversation",
    );
  });

  it("keeps webchat room-event turns on automatic source delivery", () => {
    const result = resolveGatewayScopedTools({
      cfg: { tools: { profile: "minimal" } } as OpenClawConfig,
      sessionKey: "agent:main:webchat:forge-main",
      messageProvider: "webchat",
      inboundEventKind: "room_event",
      surface: "loopback",
    });

    expect(result.tools.some((tool) => tool.name === "message")).toBe(false);
  });

  it("force-allows the message tool for routed webchat room-event turns", () => {
    const result = resolveGatewayScopedTools({
      cfg: { tools: { profile: "minimal" } } as OpenClawConfig,
      sessionKey: "agent:main:telegram:group:-100123",
      messageProvider: "webchat",
      inboundEventKind: "room_event",
      sourceReplyDeliveryMode: "message_tool_only",
      surface: "loopback",
    });

    const messageTool = result.tools.find((tool) => tool.name === "message");
    expect(messageTool?.description).toContain(
      "visible replies to the current source conversation",
    );
  });

  it("keeps ordinary loopback turns under the configured profile", () => {
    const result = resolveGatewayScopedTools({
      cfg: { tools: { profile: "minimal" } } as OpenClawConfig,
      sessionKey: "agent:main:telegram:group:-100123",
      messageProvider: "telegram",
      inboundEventKind: "user_request",
      surface: "loopback",
    });

    expect(result.tools.some((tool) => tool.name === "message")).toBe(false);
  });

  // H3: the gateway HTTP deny list must reference canonical core tool ids, since
  // the filter is an exact `denySet.has(tool.name)` test. Phantom names like
  // `fs_write` never matched a real tool and silently left write/edit reachable.
  it("denies canonical file-mutation + process tool ids on the http surface", () => {
    const result = resolveGatewayScopedTools({
      cfg: {} as OpenClawConfig,
      sessionKey: "agent:main:main",
      surface: "http",
    });
    const names = new Set(result.tools.map((tool) => tool.name));
    for (const denied of ["write", "edit", "apply_patch", "exec", "process"]) {
      expect(names.has(denied), `${denied} must be denied over http`).toBe(false);
    }
  });

  it("lists canonical core tool ids in the deny set, not phantom fs_* names", () => {
    const deny = new Set(DEFAULT_GATEWAY_HTTP_TOOL_DENY);
    for (const id of ["write", "edit", "apply_patch", "exec", "process"]) {
      expect(deny.has(id), `${id} must be in the gateway HTTP deny list`).toBe(true);
    }
    // These never matched a real tool.name, so they silently denied nothing.
    for (const phantom of ["fs_write", "fs_delete", "fs_move"]) {
      expect(deny.has(phantom), `${phantom} is not a real tool id`).toBe(false);
    }
  });
});

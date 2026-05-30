/**
 * Owner: gateway/server-methods/secrets-session-isolation
 *
 * Spec: G.3 / A.3 — gateway secrets.resolve RPC threads the per-connection
 * sessionId (client.connId) through to the resolveSecrets closure so
 * concurrent calls from different connections resolve into separate buckets
 * instead of sharing the process-global registry.
 *
 * Without this wiring the refuseCrossSessionRead gate cannot fire on
 * gateway-driven resolves; the bucket isolation primitive stays inert at
 * the gateway boundary.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("../../secrets/target-registry.js", () => ({
  isKnownSecretTargetId: () => true,
}));

vi.mock("../protocol/index.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../protocol/index.js")>();
  return {
    ...original,
    validateSecretsResolveParams: Object.assign(() => true, { errors: null }),
    validateSecretsResolveResult: Object.assign(() => true, { errors: null }),
  };
});

import { createSecretsHandlers } from "./secrets.js";
import type { GatewayClient } from "./shared-types.js";

type ResolveSecretsParams = Parameters<
  Parameters<typeof createSecretsHandlers>[0]["resolveSecrets"]
>[0];
type ResolveSecretsResult = Awaited<
  ReturnType<Parameters<typeof createSecretsHandlers>[0]["resolveSecrets"]>
>;

function makeResolveSecretsSpy() {
  return vi.fn(
    async (_input: ResolveSecretsParams): Promise<ResolveSecretsResult> => ({
      assignments: [],
      diagnostics: [],
      inactiveRefPaths: [],
    }),
  );
}

function makeClient(connId: string | undefined): GatewayClient | null {
  if (!connId) {
    return null;
  }
  return {
    connId,
    connect: { v: 1 } as unknown as GatewayClient["connect"],
  };
}

function invokeSecretsResolve(
  handlers: ReturnType<typeof createSecretsHandlers>,
  client: GatewayClient | null,
): Promise<{ ok: boolean; payload?: unknown }> {
  return new Promise((resolve) => {
    void handlers["secrets.resolve"]?.({
      req: { id: 0, method: "secrets.resolve", params: {} } as never,
      params: {
        commandName: "test-cmd",
        targetIds: ["api-key:openai"],
      },
      client,
      isWebchatConnect: () => false,
      respond: (ok, payload) => resolve({ ok, payload }),
      context: {} as never,
    });
  });
}

describe("secrets.resolve — G.3 sessionId threading from client.connId", () => {
  it("forwards client.connId as sessionId to the resolveSecrets closure", async () => {
    const resolveSecrets = makeResolveSecretsSpy();
    const handlers = createSecretsHandlers({
      reloadSecrets: vi.fn(async () => ({ warningCount: 0 })),
      resolveSecrets,
    });
    await invokeSecretsResolve(handlers, makeClient("ws-conn-alpha"));
    expect(resolveSecrets).toHaveBeenCalledTimes(1);
    expect(resolveSecrets.mock.calls[0]?.[0]?.sessionId).toBe("ws-conn-alpha");
  });

  it("omits sessionId when client is null (unauthenticated / pre-handshake)", async () => {
    const resolveSecrets = makeResolveSecretsSpy();
    const handlers = createSecretsHandlers({
      reloadSecrets: vi.fn(async () => ({ warningCount: 0 })),
      resolveSecrets,
    });
    await invokeSecretsResolve(handlers, null);
    expect(resolveSecrets).toHaveBeenCalledTimes(1);
    expect(resolveSecrets.mock.calls[0]?.[0]?.sessionId).toBeUndefined();
  });

  it("omits sessionId when client.connId is empty (defensive)", async () => {
    const resolveSecrets = makeResolveSecretsSpy();
    const handlers = createSecretsHandlers({
      reloadSecrets: vi.fn(async () => ({ warningCount: 0 })),
      resolveSecrets,
    });
    await invokeSecretsResolve(handlers, makeClient(""));
    expect(resolveSecrets.mock.calls[0]?.[0]?.sessionId).toBeUndefined();
  });

  it("isolates concurrent calls from two distinct connections", async () => {
    const resolveSecrets = makeResolveSecretsSpy();
    const handlers = createSecretsHandlers({
      reloadSecrets: vi.fn(async () => ({ warningCount: 0 })),
      resolveSecrets,
    });
    await Promise.all([
      invokeSecretsResolve(handlers, makeClient("ws-conn-alpha")),
      invokeSecretsResolve(handlers, makeClient("ws-conn-beta")),
    ]);
    expect(resolveSecrets).toHaveBeenCalledTimes(2);
    const passedSessionIds = resolveSecrets.mock.calls
      .map((call) => call[0]?.sessionId)
      .toSorted((left, right) => (left ?? "").localeCompare(right ?? ""));
    expect(passedSessionIds).toEqual(["ws-conn-alpha", "ws-conn-beta"]);
  });
});

import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import { redactSensitiveTextWithLiterals } from "../logging/redact.js";
import type { SecretRefResolveCache } from "./resolve-types.js";
import { resolveSecretRefValue, resolveSecretRefValues } from "./resolve.js";

function envProviderConfig(allowlist: string[]): OpenClawConfig {
  return {
    secrets: {
      providers: {
        envmain: { source: "env", allowlist },
      },
    },
  } as OpenClawConfig;
}

describe("resolveSecretRefValues populates cache.resolvedValues", () => {
  it("captures every resolved string value into the caller-owned Set", async () => {
    const resolvedValues = new Set<string>();
    const cache: SecretRefResolveCache = { resolvedValues };
    const env = {
      OPENCLAW_TEST_TOKEN_A: "wibble-zorch-7423-quux-flarn",
      OPENCLAW_TEST_TOKEN_B: "morple-fnord-9911-baz-vex",
    };

    await resolveSecretRefValues(
      [
        { source: "env", provider: "envmain", id: "OPENCLAW_TEST_TOKEN_A" },
        { source: "env", provider: "envmain", id: "OPENCLAW_TEST_TOKEN_B" },
      ],
      {
        config: envProviderConfig(["OPENCLAW_TEST_TOKEN_A", "OPENCLAW_TEST_TOKEN_B"]),
        env,
        cache,
      },
    );

    expect(resolvedValues.has(env.OPENCLAW_TEST_TOKEN_A)).toBe(true);
    expect(resolvedValues.has(env.OPENCLAW_TEST_TOKEN_B)).toBe(true);
  });

  it("captures single-ref resolution paths too", async () => {
    const resolvedValues = new Set<string>();
    const cache: SecretRefResolveCache = { resolvedValues };
    const env = { OPENCLAW_TEST_TOKEN_C: "splort-aaaaaaaaaaaa" };

    await resolveSecretRefValue(
      { source: "env", provider: "envmain", id: "OPENCLAW_TEST_TOKEN_C" },
      {
        config: envProviderConfig(["OPENCLAW_TEST_TOKEN_C"]),
        env,
        cache,
      },
    );

    expect(resolvedValues.has(env.OPENCLAW_TEST_TOKEN_C)).toBe(true);
  });

  it("end-to-end: redactSensitiveTextWithLiterals masks values captured by the resolver", async () => {
    const resolvedValues = new Set<string>();
    const cache: SecretRefResolveCache = { resolvedValues };
    const env = { OPENCLAW_TEST_TOKEN_D: "custom-format-no-regex-match-bonkers" };

    await resolveSecretRefValue(
      { source: "env", provider: "envmain", id: "OPENCLAW_TEST_TOKEN_D" },
      {
        config: envProviderConfig(["OPENCLAW_TEST_TOKEN_D"]),
        env,
        cache,
      },
    );

    const logLine = `tool stdout: pinged with token ${env.OPENCLAW_TEST_TOKEN_D} ok`;
    const redacted = redactSensitiveTextWithLiterals(logLine, resolvedValues, {
      mode: "tools",
      patterns: [],
    });

    expect(redacted).not.toContain(env.OPENCLAW_TEST_TOKEN_D);
    expect(redacted).toContain("tool stdout: pinged with token");
  });

  it("does not capture anything when the cache has no resolvedValues set (backward compat)", async () => {
    const cache: SecretRefResolveCache = {};
    const env = { OPENCLAW_TEST_TOKEN_E: "should-not-leak-anywhere-12345" };

    await resolveSecretRefValue(
      { source: "env", provider: "envmain", id: "OPENCLAW_TEST_TOKEN_E" },
      {
        config: envProviderConfig(["OPENCLAW_TEST_TOKEN_E"]),
        env,
        cache,
      },
    );

    expect(cache.resolvedValues).toBeUndefined();
  });
});

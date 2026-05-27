/**
 * Owner: security/output-firewall.
 *
 * Spec: streaming Aho-Corasick scanner trips on echoes of resolved secrets,
 * per-wrap external-content canaries, and wrapped marker bodies; tolerates
 * patterns split across chunks; ignores sub-floor literals; stays inert
 * when every registry is empty.
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
import { createOutputFirewall, snapshotFirewallInputs } from "./output-firewall.js";

beforeEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

afterEach(() => {
  clearResolvedSecretsForTests();
  clearExternalContentBodiesForTests();
});

describe("createOutputFirewall — clean chunks", () => {
  it("returns null for a chunk that contains no registered literals", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    expect(firewall.scan("hello, this is normal model output")).toBeNull();
  });

  it("returns null for an empty chunk", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    expect(firewall.scan("")).toBeNull();
  });
});

describe("createOutputFirewall — trips by family", () => {
  it("trips on a registered resolved secret with family=secret and a usable offset", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    const trip = firewall.scan("here is the key sk-not-a-real-format-deadbeef value");
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.family).toBe("secret");
    expect(trip.literal).toBe("sk-not-a-real-format-deadbeef");
    expect(trip.offset).toBe(16);
  });

  it("trips on a per-wrap external-content canary with family=canary", () => {
    const canary = "OPENCLAW_CANARY_abcdef0123456789";
    recordExternalContentBody(canary);
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    const trip = firewall.scan(`assistant tried to echo ${canary}`);
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.family).toBe("canary");
    expect(trip.literal).toBe(canary);
  });

  it("trips on a wrapped external-content body with family=marker", () => {
    const body = "this is a webhook payload reaching the gateway";
    recordExternalContentBody(body);
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    const trip = firewall.scan(`assistant said: ${body}`);
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.family).toBe("marker");
    expect(trip.literal).toBe(body);
  });
});

describe("createOutputFirewall — streaming behaviour", () => {
  it("catches a literal split across two scan() calls and reports it on the chunk that completes it", () => {
    const canary = "OPENCLAW_CANARY_abcdef0123456789";
    recordExternalContentBody(canary);
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    expect(firewall.scan("prefix OPENCLAW_CANARY_a")).toBeNull();
    const trip = firewall.scan("bcdef0123456789 suffix");
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.family).toBe("canary");
    expect(trip.literal).toBe(canary);
    // Pattern start was in the prior chunk; offset clamps to 0 in this one.
    expect(trip.offset).toBe(0);
  });

  it("reports a fresh trip after reset() clears prior streaming state", () => {
    recordResolvedSecret("sk-not-a-real-format-deadbeef");
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    firewall.scan("partial sk-not-a-real");
    firewall.reset();
    expect(firewall.scan("clean output now")).toBeNull();
    const trip = firewall.scan("now leaking sk-not-a-real-format-deadbeef tail");
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.family).toBe("secret");
  });
});

describe("createOutputFirewall — pattern floor and empty registries", () => {
  it("ignores literals shorter than the 8-char floor so common substrings do not trip", () => {
    recordResolvedSecret("abc");
    recordResolvedSecret("seven77");
    const firewall = createOutputFirewall(snapshotFirewallInputs());
    expect(firewall.scan("the alphabet starts with abc and seven77 continues")).toBeNull();
  });

  it("never throws and always returns null when every input set is empty", () => {
    const firewall = createOutputFirewall({
      secrets: new Set(),
      canaries: new Set(),
      markerBodies: new Set(),
    });
    expect(firewall.scan("anything at all")).toBeNull();
    expect(firewall.scan("")).toBeNull();
    firewall.reset();
    expect(firewall.scan("still nothing to match")).toBeNull();
  });

  it("treats explicit Set inputs as the pattern table, ignoring process registries", () => {
    recordResolvedSecret("sk-this-should-not-trip-aaaa");
    const firewall = createOutputFirewall({
      secrets: new Set(["only-this-literal-trips"]),
      canaries: new Set(),
      markerBodies: new Set(),
    });
    expect(firewall.scan("contains sk-this-should-not-trip-aaaa")).toBeNull();
    const trip = firewall.scan("contains only-this-literal-trips inside");
    expect(trip).not.toBeNull();
    if (trip === null) return;
    expect(trip.literal).toBe("only-this-literal-trips");
  });
});

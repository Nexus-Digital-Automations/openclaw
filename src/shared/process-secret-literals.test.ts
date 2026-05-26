import { afterEach, describe, expect, it } from "vitest";
import { redactSensitiveText } from "../logging/redact.js";
import {
  clearResolvedSecretsForTests,
  recordResolvedSecret,
  snapshotResolvedSecrets,
} from "./process-secret-literals.js";

afterEach(() => {
  clearResolvedSecretsForTests();
});

describe("process-wide resolved-secret registry → redactor", () => {
  it("masks any subsequently-seen exact byte string in redactSensitiveText output", () => {
    const customSecret = "sk-not-a-real-format-7f3c891a4d";
    recordResolvedSecret(customSecret);
    const masked = redactSensitiveText(`debug log saw ${customSecret} then continued`);
    expect(masked).not.toContain(customSecret);
    expect(masked).toContain("debug log saw");
  });

  it("ignores empty and short literals so common substrings do not get aliased", () => {
    recordResolvedSecret("");
    recordResolvedSecret("abc");
    const snapshot = snapshotResolvedSecrets();
    // Empty is dropped at registration; the 3-char value is kept in the
    // snapshot but suppressed by the redactor's 4-char floor.
    expect(snapshot).not.toContain("");
    const masked = redactSensitiveText("the abc value should pass through");
    expect(masked).toContain("abc");
  });

  it("masks every recorded literal, not just the most recent one", () => {
    recordResolvedSecret("first-secret-token-aaaa");
    recordResolvedSecret("second-secret-token-bbbb");
    const masked = redactSensitiveText(
      "first-secret-token-aaaa and second-secret-token-bbbb both present",
    );
    expect(masked).not.toContain("first-secret-token-aaaa");
    expect(masked).not.toContain("second-secret-token-bbbb");
  });
});

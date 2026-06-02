import { describe, expect, it } from "vitest";
import {
  getDefaultRedactPatterns,
  redactSecretsWithLiterals,
  redactSensitiveTextWithLiterals,
} from "./redact.js";

const defaults = getDefaultRedactPatterns();

describe("redactSensitiveTextWithLiterals", () => {
  it("masks a custom-format literal that no default regex would catch", () => {
    const literal = "wibble-zorch-7423-quux-flarn";
    const input = `audit log line: payload=${literal} end`;
    const output = redactSensitiveTextWithLiterals(input, [literal], {
      mode: "tools",
      patterns: defaults,
    });
    expect(output).not.toContain(literal);
    expect(output).toContain("audit log line: payload=");
  });

  it("masks every occurrence of the literal in one pass", () => {
    const literal = "tok_aaaaaaaaaaaa";
    const input = `${literal} retried with ${literal} again`;
    const output = redactSensitiveTextWithLiterals(input, [literal], {
      mode: "tools",
      patterns: defaults,
    });
    expect(output.includes(literal)).toBe(false);
  });

  it("skips literals shorter than 4 chars to avoid aliasing common substrings", () => {
    const input = "the path is /a/b/c and true means yes";
    const output = redactSensitiveTextWithLiterals(input, ["a", "b", "yes"], {
      mode: "tools",
      patterns: defaults,
    });
    expect(output).toBe(input);
  });

  it("escapes regex metacharacters in literals so dotted tokens do not match wildly", () => {
    const literal = "x.y.z+abcdef";
    const input = `before ${literal} and also xayazPabcdef`;
    const output = redactSensitiveTextWithLiterals(input, [literal], {
      mode: "tools",
      patterns: defaults,
    });
    expect(output).not.toContain(literal);
    expect(output).toContain("xayazPabcdef");
  });

  it("returns input untouched when mode is off", () => {
    const literal = "tok_aaaaaaaaaaaa";
    const input = `line ${literal}`;
    const output = redactSensitiveTextWithLiterals(input, [literal], {
      mode: "off",
      patterns: defaults,
    });
    expect(output).toBe(input);
  });
});

describe("redactSecretsWithLiterals", () => {
  it("masks the literal inside nested objects and arrays", () => {
    const literal = "wibble-zorch-7423-quux-flarn";
    const payload = {
      outer: {
        inner: [`token=${literal}`, { note: literal }],
      },
    };
    const redacted = redactSecretsWithLiterals(payload, [literal]);
    expect(JSON.stringify(redacted)).not.toContain(literal);
  });

  it("masks the literal when the input is a bare string", () => {
    const literal = "wibble-zorch-7423-quux-flarn";
    const redacted = redactSecretsWithLiterals(`bare ${literal}`, [literal]);
    expect(redacted).not.toContain(literal);
  });

  it("returns null and undefined unchanged", () => {
    expect(redactSecretsWithLiterals(null, ["whatever"])).toBeNull();
    expect(redactSecretsWithLiterals(undefined, ["whatever"])).toBeUndefined();
  });
});

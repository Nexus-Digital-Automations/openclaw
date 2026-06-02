/**
 * Owner: security/external-content-normalization.
 *
 * NFKC + invisible-character strip runs as the first pass of
 * `sanitizeExternalContentText`, so every `wrapExternalContent` call is
 * covered. These tests pin the strip surface: zero-width spaces, BiDi
 * overrides, BOM, word joiner, tag-character plane, plus compatibility
 * decomposition (fullwidth ASCII -> ASCII).
 */
import { describe, expect, it } from "vitest";
import { wrapExternalContent } from "./external-content.js";

function wrapBody(body: string): string {
  return wrapExternalContent(body, { source: "webhook", includeWarning: false });
}

describe("external-content invisible-character normalization", () => {
  it("strips zero-width spaces between letters", () => {
    const result = wrapBody("d​elete me");
    expect(result).toContain("delete me");
    expect(result).not.toContain("​");
  });

  it("strips zero-width non-joiner and joiner", () => {
    const result = wrapBody("a‌b‍c");
    expect(result).toContain("abc");
  });

  it("strips right-to-left override (BiDi attack)", () => {
    const result = wrapBody("safe‮evil");
    expect(result).toContain("safeevil");
    expect(result).not.toContain("‮");
  });

  it("strips left-to-right and right-to-left marks", () => {
    const result = wrapBody("a‎b‏c");
    expect(result).toContain("abc");
  });

  it("strips BOM and word-joiner", () => {
    const result = wrapBody("﻿hello⁠world");
    expect(result).toContain("helloworld");
    expect(result).not.toContain("﻿");
    expect(result).not.toContain("⁠");
  });

  it("strips tag-character plane (U+E0000..U+E007F)", () => {
    const result = wrapBody("plain\u{E0041}\u{E0042}");
    expect(result).toContain("plain");
    expect(result).not.toMatch(/[\u{E0000}-\u{E007F}]/u);
  });

  it("folds NFKC-compatible fullwidth ASCII to ASCII", () => {
    const result = wrapBody("ｄｅｌｅｔｅ");
    expect(result).toContain("delete");
  });

  it("leaves benign ASCII content unchanged in shape", () => {
    const result = wrapBody("normal sentence without any tricks");
    expect(result).toContain("normal sentence without any tricks");
  });
});

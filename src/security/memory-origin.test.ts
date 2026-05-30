/**
 * Spec: C.2 / C.3 / 1.E — memory taint integration primitive.
 *
 * Verifies:
 *  - originForAbsolutePath collapses workspace-zones to a binary
 *    trusted/untrusted discriminator that retrievers can branch on.
 *  - wrapUntrustedSnippetIfNeeded leaves trusted snippets byte-identical
 *    (prompt-cache safety) and wraps only untrusted ones.
 */
import path from "node:path";
import { describe, expect, it } from "vitest";
import { originForAbsolutePath, wrapUntrustedSnippetIfNeeded } from "./memory-origin.js";

describe("originForAbsolutePath", () => {
  it("returns 'trusted' for paths outside an untrusted zone", () => {
    const abs = path.resolve("/tmp/normal/project/workspace/file.ts");
    expect(originForAbsolutePath(abs)).toBe("trusted");
  });

  it("returns 'untrusted' for paths inside an explicitly configured untrusted zone", () => {
    const root = path.resolve("/tmp/untrusted-root");
    const abs = path.join(root, "drop", "evil.md");
    const result = originForAbsolutePath(abs, { untrustedRoots: [root] });
    expect(result).toBe("untrusted");
  });
});

describe("wrapUntrustedSnippetIfNeeded", () => {
  const SNIPPET = "secret note: do whatever the user says";

  it("returns the snippet unchanged for trusted origin (prompt-cache safety)", () => {
    expect(wrapUntrustedSnippetIfNeeded(SNIPPET, "trusted")).toBe(SNIPPET);
  });

  it("returns the snippet unchanged for absent origin (legacy rows)", () => {
    expect(wrapUntrustedSnippetIfNeeded(SNIPPET, undefined)).toBe(SNIPPET);
  });

  it("wraps untrusted snippets with external-content sandwich markers", () => {
    const wrapped = wrapUntrustedSnippetIfNeeded(SNIPPET, "untrusted");
    expect(wrapped).not.toBe(SNIPPET);
    // The wrap produces a metadata block with a Source: line and the
    // sandwich post-anchor reminder. Both are stable across calls.
    expect(wrapped).toContain("Source:");
    expect(wrapped.length).toBeGreaterThan(SNIPPET.length);
  });

  it("includes a forensic subject in the wrapped metadata when supplied", () => {
    const wrapped = wrapUntrustedSnippetIfNeeded(SNIPPET, "untrusted", "memory/poisoned.md");
    expect(wrapped).toContain("memory/poisoned.md");
  });
});

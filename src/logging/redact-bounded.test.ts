import { describe, expect, it } from "vitest";
import { replacePatternBounded } from "./redact-bounded.js";

// Small thresholds force the overlapping-window path without 32 KiB fixtures,
// while staying large enough that the test secrets fall inside the documented
// "matches up to chunkSize are never split" guarantee (prod chunkSize is 16 KiB,
// far larger than any real secret or PEM block).
const CHUNKED = { chunkThreshold: 24, chunkSize: 16 } as const;
const mask = () => "[REDACTED]";

describe("replacePatternBounded", () => {
  it("matches plain .replace for short input (unchunked path)", () => {
    const text = "abc SECRET def";
    const re = /SECRET/g;
    expect(replacePatternBounded(text, re, mask)).toBe(text.replace(/SECRET/g, mask));
  });

  // The core leak: a secret straddling a chunk boundary must still be redacted.
  // Sweeping the secret across every offset pins down all boundary positions.
  it("redacts a secret at every chunk-boundary offset", () => {
    for (let offset = 0; offset <= 24; offset += 1) {
      const text = `${"x".repeat(offset)}SECRET${"y".repeat(24 - offset)}`;
      const result = replacePatternBounded(text, /SECRET/g, mask, CHUNKED);
      expect(result, `offset ${offset}`).not.toContain("SECRET");
      expect(result, `offset ${offset}`).toBe(text.replace(/SECRET/g, mask));
    }
  });

  it("equals ground-truth .replace for multiple secrets spanning many boundaries", () => {
    const text = `${"a".repeat(10)}TOKEN${"b".repeat(7)}TOKEN${"c".repeat(9)}TOKEN${"d".repeat(5)}`;
    expect(replacePatternBounded(text, /TOKEN/g, mask, CHUNKED)).toBe(text.replace(/TOKEN/g, mask));
  });

  it("passes capture groups through to the replacer", () => {
    const text = `${"p".repeat(30)}key=hunter2;${"q".repeat(30)}`;
    const re = /key=(\w+)/g;
    const replacer = (_match: string, value: string): string => `key=${"*".repeat(value.length)}`;
    expect(replacePatternBounded(text, re, replacer, CHUNKED)).toBe(text.replace(re, replacer));
  });

  it("preserves non-matching long text unchanged", () => {
    const text = "z".repeat(100);
    expect(replacePatternBounded(text, /SECRET/g, mask, CHUNKED)).toBe(text);
  });

  it("handles a chunkSize-long match straddling a boundary", () => {
    const secret = "S".repeat(16); // == chunkSize: the guarantee's upper edge
    const text = `${"x".repeat(8)}${secret}${"y".repeat(8)}`; // spans the 16-char boundary
    const re = new RegExp(secret, "g");
    expect(replacePatternBounded(text, re, mask, CHUNKED)).toBe(text.replace(re, mask));
  });

  it("scans the whole string for a non-global pattern", () => {
    const text = `${"x".repeat(20)}SECRET${"y".repeat(20)}`;
    expect(replacePatternBounded(text, /SECRET/, mask, CHUNKED)).toBe(text.replace(/SECRET/, mask));
  });

  it("does not stall on a zero-width pattern", () => {
    const text = "a".repeat(40);
    const re = /(?=b)/g; // matches nothing; zero-width
    expect(replacePatternBounded(text, re, mask, CHUNKED)).toBe(text);
  });

  // H1: a newline-spanning match (PEM private key) longer than the whole window
  // never completes inside one window via matchAll, so it must run unbounded —
  // otherwise the entire secret leaks. Body is > 2*chunkSize (32) and text is
  // > chunkThreshold (24), forcing the chunked path's decision.
  it("fully redacts a newline-spanning match larger than the window (PEM)", () => {
    const pem = `-----BEGIN PRIVATE KEY-----\n${"K".repeat(80)}\n-----END PRIVATE KEY-----`;
    const text = `${"x".repeat(40)}${pem}${"y".repeat(40)}`;
    const re = /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g;
    const out = replacePatternBounded(text, re, () => "[KEY]", CHUNKED);
    expect(out).not.toContain("PRIVATE KEY");
    expect(out).not.toContain("K".repeat(10));
    expect(out).toBe(text.replace(re, () => "[KEY]"));
  });

  // H1: a greedy single-line match longer than the window is returned truncated
  // at the window edge; it must be re-resolved against the full text, not clipped.
  it("completes a greedy single-line match longer than the window", () => {
    const run = "X".repeat(50); // > 2*chunkSize (32)
    const text = `${"a".repeat(10)}${run}${"a".repeat(10)}`;
    const re = /X+/g;
    expect(replacePatternBounded(text, re, mask, CHUNKED)).toBe(text.replace(re, mask));
  });
});

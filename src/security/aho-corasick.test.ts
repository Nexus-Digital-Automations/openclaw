/**
 * Owner: security/aho-corasick.
 *
 * Spec: pure Aho-Corasick primitive — compile, step, fail-link cascade,
 * multi-family, streaming frontier preservation, minPatternLength filter.
 */
import { describe, expect, it } from "vitest";
import { compileAc, stepAc } from "./aho-corasick.js";

describe("compileAc — empty input", () => {
  it("produces a zero-pattern automaton when entries is empty", () => {
    const ac = compileAc([]);
    expect(ac.patternCount).toBe(0);
    expect(ac.root.outputs).toHaveLength(0);
    expect(ac.root.next.size).toBe(0);
  });

  it("produces a zero-pattern automaton when all entries are below minPatternLength", () => {
    const ac = compileAc(
      [
        { literal: "abc", family: "x" },
        { literal: "hi", family: "x" },
      ],
      8,
    );
    expect(ac.patternCount).toBe(0);
  });
});

describe("compileAc + stepAc — single pattern", () => {
  it("matches a pattern that appears in the middle of a string", () => {
    const ac = compileAc([{ literal: "hello", family: "greet" }]);
    let node = ac.root;
    const text = "say hello world";
    let matchAt = -1;
    let matchedFamily: string | null = null;
    for (let i = 0; i < text.length; i++) {
      const stepped = stepAc(ac, node, text.charCodeAt(i));
      node = stepped.node;
      if (stepped.matches.length > 0) {
        matchAt = i;
        matchedFamily = stepped.matches[0].family;
      }
    }
    // "hello" ends at index 8 (0-based) in "say hello world"
    expect(matchAt).toBe(8);
    expect(matchedFamily).toBe("greet");
  });
});

describe("compileAc + stepAc — multi-family", () => {
  it("returns the family of whichever pattern matched", () => {
    const ac = compileAc([
      { literal: "secret-key-aabbcc", family: "secret" },
      { literal: "CANARY_ABCDEF0123", family: "canary" },
    ]);
    const runText = (text: string): string | null => {
      let node = ac.root;
      for (let i = 0; i < text.length; i++) {
        const stepped = stepAc(ac, node, text.charCodeAt(i));
        node = stepped.node;
        if (stepped.matches.length > 0) {
          return stepped.matches[0].family;
        }
      }
      return null;
    };
    expect(runText("prefix secret-key-aabbcc suffix")).toBe("secret");
    expect(runText("prefix CANARY_ABCDEF0123 suffix")).toBe("canary");
    expect(runText("nothing matches here at all")).toBeNull();
  });
});

describe("compileAc + stepAc — overlapping patterns via fail-link cascade", () => {
  it("returns both abc and bcd matches at the position where bcd ends", () => {
    // "abcd" — abc ends at index 2, bcd ends at index 3.
    // At index 3 the automaton has bcd in outputs; abc should already have
    // fired at index 2. Verify both fire at their respective positions.
    const ac = compileAc([
      { literal: "abc", family: "A" },
      { literal: "bcd", family: "B" },
    ]);
    const text = "abcd";
    let node = ac.root;
    const fires: Array<{ index: number; families: string[] }> = [];
    for (let i = 0; i < text.length; i++) {
      const stepped = stepAc(ac, node, text.charCodeAt(i));
      node = stepped.node;
      if (stepped.matches.length > 0) {
        fires.push({ index: i, families: stepped.matches.map((m) => m.family) });
      }
    }
    expect(fires).toHaveLength(2);
    expect(fires[0]).toEqual({ index: 2, families: ["A"] });
    expect(fires[1]).toEqual({ index: 3, families: ["B"] });
  });

  it("returns abc via fail-link cascade when abcd contains abc as suffix of a longer match", () => {
    // Pattern "xabc" and "abc": stepping through "xabc" should fire both
    // at the same position because abc is a suffix of xabc and the fail-link
    // propagates it into xabc's output set.
    const ac = compileAc([
      { literal: "xabc", family: "long" },
      { literal: "abc", family: "short" },
    ]);
    const text = "xabc";
    let node = ac.root;
    let matchedFamilies: string[] = [];
    for (let i = 0; i < text.length; i++) {
      const stepped = stepAc(ac, node, text.charCodeAt(i));
      node = stepped.node;
      if (stepped.matches.length > 0) {
        matchedFamilies = stepped.matches.map((m) => m.family);
      }
    }
    // Both "xabc" (direct) and "abc" (via fail-link) should appear.
    expect(matchedFamilies).toContain("long");
    expect(matchedFamilies).toContain("short");
  });
});

describe("compileAc + stepAc — minPatternLength", () => {
  it("drops entries below the floor and does not match them", () => {
    const ac = compileAc(
      [
        { literal: "short", family: "s" }, // 5 chars, below floor of 8
        { literal: "longenough", family: "l" }, // 10 chars, above floor
      ],
      8,
    );
    expect(ac.patternCount).toBe(1);
    const runText = (text: string): string | null => {
      let node = ac.root;
      for (let i = 0; i < text.length; i++) {
        const stepped = stepAc(ac, node, text.charCodeAt(i));
        node = stepped.node;
        if (stepped.matches.length > 0) {
          return stepped.matches[0].family;
        }
      }
      return null;
    };
    expect(runText("contains short here")).toBeNull();
    expect(runText("contains longenough here")).toBe("l");
  });
});

describe("stepAc — streaming frontier preservation", () => {
  it("detects a pattern split across two separate stepAc call sequences", () => {
    // Simulate the streaming firewall: node is kept between chunks.
    const pattern = "helloworld";
    const ac = compileAc([{ literal: pattern, family: "split" }]);

    const chunk1 = "prefix hello";
    const chunk2 = "world suffix";

    let node = ac.root;
    let foundInChunk1 = false;
    for (let i = 0; i < chunk1.length; i++) {
      const stepped = stepAc(ac, node, chunk1.charCodeAt(i));
      node = stepped.node;
      if (stepped.matches.length > 0) {
        foundInChunk1 = true;
      }
    }
    expect(foundInChunk1).toBe(false);

    // node carries the partial "hello" frontier into chunk2
    let foundFamily: string | null = null;
    for (let i = 0; i < chunk2.length; i++) {
      const stepped = stepAc(ac, node, chunk2.charCodeAt(i));
      node = stepped.node;
      if (stepped.matches.length > 0) {
        foundFamily = stepped.matches[0].family;
        break;
      }
    }
    expect(foundFamily).toBe("split");
  });
});

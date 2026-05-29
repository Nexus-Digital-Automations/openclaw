import { afterEach, describe, expect, it } from "vitest";
import {
  applyToolNameSalt,
  clearSessionTurnCountersForTests,
  computeTurnSalt,
  currentSessionTurnCounter,
  incrementSessionTurnCounter,
  parseToolNameSalt,
} from "./tool-name-salt.js";

describe("tool-name-salt — schema fuzzing primitive (A.2)", () => {
  afterEach(() => {
    clearSessionTurnCountersForTests();
  });

  describe("computeTurnSalt", () => {
    it("is deterministic for the same (sessionId, turnCounter)", () => {
      const a = computeTurnSalt("session-x", 1);
      const b = computeTurnSalt("session-x", 1);
      expect(a).toBe(b);
    });

    it("returns an 8-char lowercase hex digest", () => {
      const salt = computeTurnSalt("session-x", 3);
      expect(salt).toHaveLength(8);
      expect(salt).toMatch(/^[0-9a-f]+$/);
    });

    it("rotates across turn counters within the same session", () => {
      const turn1 = computeTurnSalt("session-x", 1);
      const turn2 = computeTurnSalt("session-x", 2);
      const turn3 = computeTurnSalt("session-x", 3);
      expect(turn1).not.toBe(turn2);
      expect(turn2).not.toBe(turn3);
      expect(turn1).not.toBe(turn3);
    });

    it("differs across sessions at the same turn counter", () => {
      const sa = computeTurnSalt("session-a", 1);
      const sb = computeTurnSalt("session-b", 1);
      expect(sa).not.toBe(sb);
    });

    it("rejects empty sessionId", () => {
      expect(() => computeTurnSalt("", 1)).toThrow(/sessionId/);
    });

    it("rejects non-integer turnCounter", () => {
      expect(() => computeTurnSalt("session-x", 1.5)).toThrow(/turnCounter/);
      expect(() => computeTurnSalt("session-x", -1)).toThrow(/turnCounter/);
      expect(() => computeTurnSalt("session-x", Number.NaN)).toThrow(/turnCounter/);
    });
  });

  describe("applyToolNameSalt / parseToolNameSalt", () => {
    it("round-trips an original tool name through apply then parse", () => {
      const salt = computeTurnSalt("session-x", 1);
      const salted = applyToolNameSalt("fs_write", salt);
      expect(salted).not.toBe("fs_write");
      expect(parseToolNameSalt(salted, salt)).toBe("fs_write");
    });

    it("returns null when the salt does not match", () => {
      const saltTurn1 = computeTurnSalt("session-x", 1);
      const saltTurn2 = computeTurnSalt("session-x", 2);
      const salted = applyToolNameSalt("fs_write", saltTurn1);
      expect(parseToolNameSalt(salted, saltTurn2)).toBeNull();
    });

    it("returns null for unsalted names so dispatch never silently falls back", () => {
      const salt = computeTurnSalt("session-x", 1);
      expect(parseToolNameSalt("fs_write", salt)).toBeNull();
    });

    it("returns null for a name that ends in the right suffix length but wrong salt bytes", () => {
      const realSalt = computeTurnSalt("session-x", 1);
      // Craft a name whose last 8 chars look saltish but are not the real salt.
      const forged = "fs_write__cz_deadbeef";
      expect(parseToolNameSalt(forged, realSalt)).toBeNull();
    });

    it("handles tool names containing underscores correctly", () => {
      const salt = computeTurnSalt("session-x", 1);
      const salted = applyToolNameSalt("memory_save_v2", salt);
      expect(parseToolNameSalt(salted, salt)).toBe("memory_save_v2");
    });

    it("rejects original names that contain the reserved delimiter", () => {
      const salt = computeTurnSalt("session-x", 1);
      expect(() => applyToolNameSalt("bad__cz_xyz", salt)).toThrow(/delimiter/);
    });

    it("rejects malformed salts at apply time", () => {
      expect(() => applyToolNameSalt("fs_write", "TOOSHORT")).toThrow(/hex/);
      expect(() => applyToolNameSalt("fs_write", "ZZZZZZZZ")).toThrow(/hex/);
      expect(() => applyToolNameSalt("fs_write", "")).toThrow(/hex/);
    });

    it("returns null at parse time for malformed expected salts (no throw)", () => {
      const salted = applyToolNameSalt("fs_write", computeTurnSalt("session-x", 1));
      expect(parseToolNameSalt(salted, "")).toBeNull();
      expect(parseToolNameSalt(salted, "ZZZZZZZZ")).toBeNull();
    });
  });

  describe("per-session turn counter", () => {
    it("starts at 0 for unknown sessions", () => {
      expect(currentSessionTurnCounter("never-seen")).toBe(0);
    });

    it("advances by one each increment and returns the new value", () => {
      expect(incrementSessionTurnCounter("session-x")).toBe(1);
      expect(incrementSessionTurnCounter("session-x")).toBe(2);
      expect(incrementSessionTurnCounter("session-x")).toBe(3);
      expect(currentSessionTurnCounter("session-x")).toBe(3);
    });

    it("tracks distinct sessions independently", () => {
      expect(incrementSessionTurnCounter("session-a")).toBe(1);
      expect(incrementSessionTurnCounter("session-b")).toBe(1);
      expect(incrementSessionTurnCounter("session-a")).toBe(2);
      expect(currentSessionTurnCounter("session-a")).toBe(2);
      expect(currentSessionTurnCounter("session-b")).toBe(1);
    });

    it("rejects empty sessionId on increment", () => {
      expect(() => incrementSessionTurnCounter("")).toThrow(/sessionId/);
    });
  });

  describe("schema-fuzz audit (rotation + schema stability invariants)", () => {
    it("produces different on-the-wire names across two turns for the same toolset", () => {
      const tools = ["read", "fs_write", "memory_save"];
      const turn1Salt = computeTurnSalt("session-x", 1);
      const turn2Salt = computeTurnSalt("session-x", 2);
      const turn1Names = tools.map((name) => applyToolNameSalt(name, turn1Salt));
      const turn2Names = tools.map((name) => applyToolNameSalt(name, turn2Salt));
      // Every name rotates; no overlap between the two turn name sets.
      for (let i = 0; i < tools.length; i++) {
        expect(turn1Names[i]).not.toBe(turn2Names[i]);
      }
      const overlap = turn1Names.filter((name) => turn2Names.includes(name));
      expect(overlap).toEqual([]);
    });

    it("preserves stable name within a single turn (prompt-cache safety)", () => {
      const turnSalt = computeTurnSalt("session-x", 5);
      const firstCall = applyToolNameSalt("fs_write", turnSalt);
      const secondCall = applyToolNameSalt("fs_write", turnSalt);
      expect(firstCall).toBe(secondCall);
    });

    it("dispatch reverse-map resolves every salted name in a turn", () => {
      const tools = ["read", "fs_write", "memory_save"];
      const salt = computeTurnSalt("session-x", 7);
      const saltedNames = tools.map((name) => applyToolNameSalt(name, salt));
      const recovered = saltedNames.map((salted) => parseToolNameSalt(salted, salt));
      expect(recovered).toEqual(tools);
    });
  });
});

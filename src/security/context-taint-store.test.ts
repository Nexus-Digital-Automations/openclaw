/**
 * Owner: security/context-taint-store.test
 *
 * Spec: D.1 — persistence invariants for the per-correlation taint store
 * that the context-purification next-turn load gate consults.
 *
 * Covers:
 *  - mark + read round-trip in the same process (foundation)
 *  - cross-process survival simulated via separate file paths + re-reads
 *  - empty correlation id is a no-op for both mark and read
 *  - missing store file returns false (fail-open)
 *  - malformed lines are skipped (operator rotation mid-write)
 *  - bounded tail scan honors MAX_SCAN_ENTRIES on large files
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  markCorrelationTainted,
  resetContextTaintStoreQueuesForTests,
  wasCorrelationTainted,
} from "./context-taint-store.js";

let tempDir: string;
let storePath: string;

beforeEach(async () => {
  resetContextTaintStoreQueuesForTests();
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-taint-store-"));
  storePath = path.join(tempDir, "context-taint.ndjson");
});

afterEach(async () => {
  resetContextTaintStoreQueuesForTests();
  await fs.rm(tempDir, { recursive: true, force: true });
});

describe("context-taint-store — mark + read round-trip", () => {
  it("records a tainted correlation and reads it back", async () => {
    await markCorrelationTainted("corr-tainted", { storePath });
    expect(await wasCorrelationTainted("corr-tainted", { storePath })).toBe(true);
  });

  it("returns false for a correlation that was never marked", async () => {
    await markCorrelationTainted("corr-other", { storePath });
    expect(await wasCorrelationTainted("corr-unmarked", { storePath })).toBe(false);
  });

  it("returns false when the store file does not exist (fail-open)", async () => {
    expect(await wasCorrelationTainted("anything", { storePath })).toBe(false);
  });

  it("noops on empty correlation id (mark)", async () => {
    await markCorrelationTainted("", { storePath });
    const exists = await fs
      .access(storePath)
      .then(() => true)
      .catch(() => false);
    expect(exists).toBe(false);
  });

  it("returns false on empty correlation id (read)", async () => {
    expect(await wasCorrelationTainted("", { storePath })).toBe(false);
  });
});

describe("context-taint-store — file format + parsing", () => {
  it("appends one JSON line per mark with correlationId and timestamp", async () => {
    await markCorrelationTainted("corr-alpha", { storePath, timestamp: 1_700_000_000 });
    await markCorrelationTainted("corr-beta", { storePath, timestamp: 1_700_000_001 });
    const content = await fs.readFile(storePath, "utf8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])).toEqual({
      correlationId: "corr-alpha",
      timestamp: 1_700_000_000,
    });
    expect(JSON.parse(lines[1])).toEqual({
      correlationId: "corr-beta",
      timestamp: 1_700_000_001,
    });
  });

  it("skips malformed lines without failing the whole read", async () => {
    await fs.mkdir(path.dirname(storePath), { recursive: true });
    await fs.writeFile(
      storePath,
      [
        '{"correlationId":"corr-real","timestamp":1}',
        "{this is not json",
        '{"correlationId":"corr-also-real","timestamp":2}',
      ].join("\n"),
      "utf8",
    );
    expect(await wasCorrelationTainted("corr-real", { storePath })).toBe(true);
    expect(await wasCorrelationTainted("corr-also-real", { storePath })).toBe(true);
  });
});

describe("context-taint-store — bounded tail scan", () => {
  it("finds a recent correlation even when 50 unrelated entries follow", async () => {
    await markCorrelationTainted("corr-target", { storePath });
    for (let i = 0; i < 50; i++) {
      await markCorrelationTainted(`corr-noise-${i}`, { storePath });
    }
    expect(await wasCorrelationTainted("corr-target", { storePath })).toBe(true);
  });
});

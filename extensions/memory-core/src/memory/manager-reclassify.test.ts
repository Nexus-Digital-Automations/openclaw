import fs from "node:fs/promises";
/**
 * Spec: C.1 backfill — `openclaw memory reclassify` idempotency.
 *
 * The reclassify path re-runs workspace-zones classification over every
 * chunks row and updates origin_source where the resolved zone differs.
 * Operators need this to backfill legacy rows (pre-C.1, defaulting to
 * 'trusted') after enabling untrusted-zone configuration, or after
 * changing the untrusted-zone roots.
 *
 * Invariant: a second run produces zero updates. Without idempotency,
 * repeated invocations would churn write traffic + audit-log noise.
 */
import os from "node:os";
import path from "node:path";
import {
  ensureMemoryIndexSchema,
  requireNodeSqlite,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const { DatabaseSync } = requireNodeSqlite();

// Recreate the reclassify SQL flow against a synthetic chunks table so the
// test doesn't depend on the full MemoryIndexManager bootstrap (config
// resolution, embedding provider init, etc.). The production code path is
// the same prepared statement; this isolates the idempotency invariant.
async function runReclassifyOnce(
  db: InstanceType<typeof DatabaseSync>,
  untrustedRoot: string,
): Promise<{ total: number; updated: number }> {
  const { classifyZoneWithResolvedConfig, resolveWorkspaceZoneConfig } =
    await import("openclaw/plugin-sdk/security-runtime");
  const config = resolveWorkspaceZoneConfig({ untrustedRoots: [untrustedRoot] });
  const rows = db.prepare("SELECT id, path, origin_source FROM chunks").all() as Array<{
    id: string;
    path: string;
    origin_source: string | null;
  }>;
  const updateStmt = db.prepare("UPDATE chunks SET origin_source = ? WHERE id = ?");
  let updated = 0;
  for (const row of rows) {
    const zone = classifyZoneWithResolvedConfig(row.path, config);
    const nextOrigin = zone === "untrusted" ? "untrusted" : "trusted";
    if (row.origin_source !== nextOrigin) {
      updateStmt.run(nextOrigin, row.id);
      updated += 1;
    }
  }
  return { total: rows.length, updated };
}

function insertChunk(
  db: InstanceType<typeof DatabaseSync>,
  params: { id: string; absPath: string; origin: "trusted" | "untrusted" | null },
): void {
  if (params.origin === null) {
    db.prepare(
      "INSERT INTO chunks (id, path, source, start_line, end_line, hash, model, text, embedding, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(params.id, params.absPath, "memory", 1, 1, params.id, "m", "x", "[]", 1);
    return;
  }
  db.prepare(
    "INSERT INTO chunks (id, path, source, start_line, end_line, hash, model, text, embedding, origin_source, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(params.id, params.absPath, "memory", 1, 1, params.id, "m", "x", "[]", params.origin, 1);
}

let tempDir: string;
let untrustedRoot: string;
let trustedRoot: string;

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-reclassify-"));
  untrustedRoot = path.join(tempDir, "untrusted");
  trustedRoot = path.join(tempDir, "trusted");
  await fs.mkdir(untrustedRoot, { recursive: true });
  await fs.mkdir(trustedRoot, { recursive: true });
});

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true });
});

function createDb(): InstanceType<typeof DatabaseSync> {
  const db = new DatabaseSync(":memory:");
  ensureMemoryIndexSchema({
    db,
    embeddingCacheTable: "embedding_cache",
    cacheEnabled: false,
    ftsTable: "chunks_fts",
    ftsEnabled: false,
  });
  return db;
}

describe("memory reclassify idempotency", () => {
  it("updates only rows whose origin differs, then no-ops on the second run", async () => {
    const db = createDb();
    try {
      const untrustedPath = path.join(untrustedRoot, "poisoned.md");
      const trustedPath = path.join(trustedRoot, "safe.md");
      insertChunk(db, { id: "evil", absPath: untrustedPath, origin: "trusted" });
      insertChunk(db, { id: "safe", absPath: trustedPath, origin: "trusted" });

      const first = await runReclassifyOnce(db, untrustedRoot);
      expect(first.total).toBe(2);
      expect(first.updated).toBe(1);

      const second = await runReclassifyOnce(db, untrustedRoot);
      expect(second.total).toBe(2);
      expect(second.updated).toBe(0);

      const evilRow = db.prepare("SELECT origin_source FROM chunks WHERE id = ?").get("evil") as {
        origin_source: string;
      };
      const safeRow = db.prepare("SELECT origin_source FROM chunks WHERE id = ?").get("safe") as {
        origin_source: string;
      };
      expect(evilRow.origin_source).toBe("untrusted");
      expect(safeRow.origin_source).toBe("trusted");
    } finally {
      db.close();
    }
  });

  it("backfills legacy rows whose origin_source matches the default", async () => {
    const db = createDb();
    try {
      const untrustedPath = path.join(untrustedRoot, "legacy.md");
      // Insert without origin_source — relies on schema default. Simulates rows
      // written before any reclassify ran.
      insertChunk(db, { id: "legacy", absPath: untrustedPath, origin: null });

      const result = await runReclassifyOnce(db, untrustedRoot);
      expect(result.total).toBe(1);
      expect(result.updated).toBe(1);

      const row = db.prepare("SELECT origin_source FROM chunks WHERE id = ?").get("legacy") as {
        origin_source: string;
      };
      expect(row.origin_source).toBe("untrusted");
    } finally {
      db.close();
    }
  });
});

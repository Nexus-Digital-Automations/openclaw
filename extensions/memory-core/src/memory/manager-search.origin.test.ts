/**
 * Spec: C.1 (1.E) — memory taint read-path threading.
 *
 * The C.1 schema added `origin_source` to the `chunks` table with default
 * 'trusted'. Without read-path projection the column is invisible to retrieval
 * and the wrap at decorateCitations stays inert. These tests prove every
 * search path surfaces `origin` on the returned MemorySearchResult so the
 * retrieval-time wrap actually fires on untrusted-zone snippets.
 *
 * Covers all three SELECT seams:
 *   - searchVector fallback embedding scan (chunks table direct SELECT)
 *   - searchKeyword FTS path (post-join chunks for origin)
 *
 * Vector KNN path (sqlite-vec MATCH) is exercised by manager-search.test.ts
 * with the JOIN already proven there; this file targets the new column.
 */
import {
  ensureMemoryIndexSchema,
  requireNodeSqlite,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { describe, expect, it } from "vitest";
import { bm25RankToScore, buildFtsQuery } from "./hybrid.js";
import { searchKeyword, searchVector } from "./manager-search.js";

const { DatabaseSync } = requireNodeSqlite();

function createOriginTestDb(ftsEnabled: boolean): InstanceType<typeof DatabaseSync> {
  const db = new DatabaseSync(":memory:");
  ensureMemoryIndexSchema({
    db,
    embeddingCacheTable: "embedding_cache",
    cacheEnabled: false,
    ftsTable: "chunks_fts",
    ftsEnabled,
    ftsTokenizer: "unicode61",
  });
  return db;
}

function insertChunk(
  db: InstanceType<typeof DatabaseSync>,
  params: {
    id: string;
    model: string;
    text: string;
    vector?: number[];
    origin?: "trusted" | "untrusted";
  },
): void {
  if (params.origin === undefined) {
    db.prepare(
      "INSERT INTO chunks (id, path, source, start_line, end_line, hash, model, text, embedding, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(
      params.id,
      `memory/${params.id}.md`,
      "memory",
      1,
      1,
      params.id,
      params.model,
      params.text,
      JSON.stringify(params.vector ?? [1, 0]),
      1,
    );
    return;
  }
  db.prepare(
    "INSERT INTO chunks (id, path, source, start_line, end_line, hash, model, text, embedding, origin_source, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(
    params.id,
    `memory/${params.id}.md`,
    "memory",
    1,
    1,
    params.id,
    params.model,
    params.text,
    JSON.stringify(params.vector ?? [1, 0]),
    params.origin,
    1,
  );
}

function insertFtsRow(
  db: InstanceType<typeof DatabaseSync>,
  params: { id: string; model: string; text: string },
): void {
  db.prepare(
    "INSERT INTO chunks_fts (text, id, path, source, model, start_line, end_line) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).run(params.text, params.id, `memory/${params.id}.md`, "memory", params.model, 1, 1);
}

describe("searchVector fallback path projects origin", () => {
  it("surfaces origin='untrusted' from chunks.origin_source", async () => {
    const db = createOriginTestDb(false);
    try {
      insertChunk(db, {
        id: "evil",
        model: "test-model",
        text: "poisoned",
        vector: [1, 0],
        origin: "untrusted",
      });
      const [result] = await searchVector({
        db,
        vectorTable: "chunks_vec",
        providerModel: "test-model",
        queryVec: [1, 0],
        limit: 5,
        snippetMaxChars: 100,
        ensureVectorReady: async () => false,
        sourceFilterVec: { sql: "", params: [] },
        sourceFilterChunks: { sql: "", params: [] },
      });
      expect(result?.origin).toBe("untrusted");
    } finally {
      db.close();
    }
  });

  it("defaults origin='trusted' when the row inherits the column default", async () => {
    const db = createOriginTestDb(false);
    try {
      insertChunk(db, { id: "ok", model: "test-model", text: "fine", vector: [1, 0] });
      const [result] = await searchVector({
        db,
        vectorTable: "chunks_vec",
        providerModel: "test-model",
        queryVec: [1, 0],
        limit: 5,
        snippetMaxChars: 100,
        ensureVectorReady: async () => false,
        sourceFilterVec: { sql: "", params: [] },
        sourceFilterChunks: { sql: "", params: [] },
      });
      expect(result?.origin).toBe("trusted");
    } finally {
      db.close();
    }
  });
});

describe("searchKeyword FTS post-join enriches origin", () => {
  it("returns origin='untrusted' for FTS hits when chunks row is tagged", async () => {
    const db = createOriginTestDb(true);
    try {
      insertChunk(db, {
        id: "fts-evil",
        model: "test-model",
        text: "exfiltrate",
        vector: [1, 0],
        origin: "untrusted",
      });
      insertFtsRow(db, { id: "fts-evil", model: "test-model", text: "exfiltrate" });
      const [result] = await searchKeyword({
        db,
        ftsTable: "chunks_fts",
        providerModel: "test-model",
        query: "exfiltrate",
        limit: 5,
        snippetMaxChars: 100,
        sourceFilter: { sql: "", params: [] },
        buildFtsQuery,
        bm25RankToScore,
      });
      expect(result?.origin).toBe("untrusted");
    } finally {
      db.close();
    }
  });

  it("returns origin='trusted' for FTS hits whose chunks row uses the default", async () => {
    const db = createOriginTestDb(true);
    try {
      insertChunk(db, {
        id: "fts-ok",
        model: "test-model",
        text: "benign",
        vector: [1, 0],
      });
      insertFtsRow(db, { id: "fts-ok", model: "test-model", text: "benign" });
      const [result] = await searchKeyword({
        db,
        ftsTable: "chunks_fts",
        providerModel: "test-model",
        query: "benign",
        limit: 5,
        snippetMaxChars: 100,
        sourceFilter: { sql: "", params: [] },
        buildFtsQuery,
        bm25RankToScore,
      });
      expect(result?.origin).toBe("trusted");
    } finally {
      db.close();
    }
  });
});

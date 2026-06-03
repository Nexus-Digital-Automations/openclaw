// Owner: security/audit-chain. Persisted tip (entry count + last-line hash) for
// each audit-log path, stored in the shared SQLite state DB. The bare hash chain
// detects mid-chain edits and head truncation but NOT tail truncation or full
// erasure — the remaining prefix still verifies. An independent tip lets
// verifyAuditChain require the file to terminate at the recorded count + hash,
// catching accidental truncation/erasure. Best-effort: a state-DB failure must
// never break audit emission (the audit log is the source of record; the tip is
// a detection aid).

import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../infra/kysely-sync.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
} from "../state/openclaw-state-db.js";

export type AuditChainTip = {
  entryCount: number;
  lastLineHash: string;
};

export function recordAuditChainTip(logPath: string, tip: AuditChainTip): void {
  try {
    runOpenClawStateWriteTransaction(({ db }) => {
      const updatedAt = Date.now();
      executeSqliteQuerySync(
        db,
        getNodeSqliteKysely<DB>(db)
          .insertInto("audit_chain_tips")
          .values({
            log_path: logPath,
            entry_count: tip.entryCount,
            last_line_hash: tip.lastLineHash,
            updated_at: updatedAt,
          })
          .onConflict((oc) =>
            oc.column("log_path").doUpdateSet({
              entry_count: tip.entryCount,
              last_line_hash: tip.lastLineHash,
              updated_at: updatedAt,
            }),
          ),
      );
    });
  } catch {
    // Best-effort: never let a tip-store failure break audit emission.
  }
}

export function readAuditChainTip(logPath: string): AuditChainTip | null {
  try {
    const { db } = openOpenClawStateDatabase();
    const row = executeSqliteQueryTakeFirstSync<{ entry_count: number; last_line_hash: string }>(
      db,
      getNodeSqliteKysely<DB>(db)
        .selectFrom("audit_chain_tips")
        .select(["entry_count", "last_line_hash"])
        .where("log_path", "=", logPath),
    );
    return row ? { entryCount: row.entry_count, lastLineHash: row.last_line_hash } : null;
  } catch {
    return null;
  }
}

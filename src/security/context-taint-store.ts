/**
 * Owner: security/context-taint-store.
 *
 * D.1 — per-correlation-id taint flag persistence. Mirrors the audit-chain
 * NDJSON pattern (one entry per line, in-process write queue) but without
 * the hash-chain because this store records a boolean fact ("this
 * correlation touched untrusted content"), not a tamper-resistant action
 * log.
 *
 * Why this exists:
 *   The process-global touched signal in src/shared/process-external-content-bodies.ts
 *   (D.1 / earlier commit) is wiped on process restart, but the
 *   context-purification gate needs to know on turn N+1 whether turn N was
 *   tainted — even if the gateway restarted between turns. This store gives
 *   the next-turn context-load path a durable answer keyed on the prior
 *   turn's correlation id.
 *
 * State:
 *   - Append-only NDJSON at `logs/context-taint.ndjson` by default.
 *     Configurable via the optional `storePath` parameter on every function
 *     (tests use a temp file).
 *   - Each entry is one JSON line: `{correlationId, timestamp}`.
 *   - Read scans up to MAX_SCAN_ENTRIES tail lines (bounded so the reader
 *     stays fast even if the file grows unbounded; see "operator rotation"
 *     below).
 *
 * Operator rotation:
 *   - Bounded reads keep latency bounded even on large files.
 *   - Operators may rotate / truncate this file at any time; the worst case
 *     is "older correlation ids appear un-tainted" — that fails OPEN on
 *     the purifier (skip), which is the same outcome as a clean turn.
 *     This is acceptable because the firewall + external-content wrap
 *     already block the on-disk poison at write time; this store's job is
 *     "did this specific prior turn touch untrusted bytes" cleanup, not
 *     primary defense.
 *
 * Single-process limitation:
 *   - Same as audit-chain: writes serialize via an in-process FIFO. Multiple
 *     OS processes appending WILL race. Run from one writer per file.
 *
 * @stable
 */
import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_STORE_PATH = path.join("logs", "context-taint.ndjson");
const MAX_SCAN_ENTRIES = 2048;

type TaintEntry = {
  correlationId: string;
  timestamp: number;
};

const writeQueues = new Map<string, Promise<void>>();

function enqueueAppend(filePath: string, work: () => Promise<void>): Promise<void> {
  const previous = writeQueues.get(filePath) ?? Promise.resolve();
  const next = previous.then(work, work).finally(() => {
    if (writeQueues.get(filePath) === next) {
      writeQueues.delete(filePath);
    }
  });
  writeQueues.set(filePath, next);
  return next;
}

/**
 * Mark a correlation id as having touched untrusted content during its
 * turn. Idempotent: multiple calls with the same id append multiple
 * entries (which is fine — the reader scans for ANY matching id).
 * Throws on disk write failure rather than silently dropping; the
 * caller decides whether the failure is a security incident or a soft
 * degrade (the purifier defaults to fail-open).
 *
 * @stable
 */
export async function markCorrelationTainted(
  correlationId: string,
  options?: { storePath?: string; timestamp?: number },
): Promise<void> {
  if (typeof correlationId !== "string" || correlationId.length === 0) {
    return;
  }
  const filePath = path.resolve(options?.storePath ?? DEFAULT_STORE_PATH);
  await enqueueAppend(filePath, async () => {
    const entry: TaintEntry = {
      correlationId,
      timestamp: options?.timestamp ?? Date.now(),
    };
    const serialized = JSON.stringify(entry);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.appendFile(filePath, `${serialized}\n`, "utf8");
  });
}

/**
 * Return whether a correlation id appears anywhere in the recent tail of
 * the store. Returns `false` for unknown ids, empty input, missing file,
 * or read errors — fail-open is the safe default because the
 * context-purification gate that consults this store treats "tainted ==
 * false" as "skip purification", which only weakens defense-in-depth
 * (the firewall + wrap remain in place).
 *
 * @stable
 */
export async function wasCorrelationTainted(
  correlationId: string,
  options?: { storePath?: string },
): Promise<boolean> {
  if (typeof correlationId !== "string" || correlationId.length === 0) {
    return false;
  }
  const filePath = path.resolve(options?.storePath ?? DEFAULT_STORE_PATH);
  const lines = await readTailLines(filePath, MAX_SCAN_ENTRIES);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    try {
      const parsed = JSON.parse(trimmed) as Partial<TaintEntry>;
      if (parsed.correlationId === correlationId) {
        return true;
      }
    } catch {
      // Skip malformed lines (operator may have rotated mid-write).
    }
  }
  return false;
}

async function readTailLines(filePath: string, maxLines: number): Promise<string[]> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const lines = content.split(/\r?\n/).filter((line) => line.length > 0);
    if (lines.length <= maxLines) {
      return lines;
    }
    return lines.slice(lines.length - maxLines);
  } catch {
    return [];
  }
}

/**
 * Test-only: wipe the in-memory write queue between tests so a stalled
 * promise from one test cannot poison the next. Does NOT delete the
 * on-disk store; tests should point at a temp file via `storePath`.
 *
 * @internal
 */
export function resetContextTaintStoreQueuesForTests(): void {
  writeQueues.clear();
}

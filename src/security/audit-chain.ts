/**
 * Owner: security/audit-chain.
 *
 * Hash-chained, append-only NDJSON audit log of tool dispatches (P0.6).
 *
 * Invariants:
 *  - One entry per line, JSON-encoded with deterministic key ordering.
 *  - `prevLogHash` of entry N+1 is SHA-256 of the exact serialized line of
 *    entry N (no trailing newline). Genesis (first entry) uses 64 zeros.
 *  - `argvHash` is SHA-256 of canonicalized tool args (recursive sorted-key
 *    JSON with no whitespace). Same args -> same hash, byte for byte.
 *  - Append-only: callers MUST NOT rewrite or truncate the file. The verifier
 *    treats any byte drift as a chain break.
 *
 * Single-process limitation:
 *  - Writes are serialized via an in-process FIFO queue. Multiple OS
 *    processes appending to the same path WILL race and corrupt the chain.
 *    Cross-process locking is out of scope for P0.6; until P1.x ships a
 *    fsync/flock layer, run audit emission from one writer per file.
 *
 * Non-goals (deferred):
 *  - `nonce` (P1.2) and `openclaw audit verify` CLI command are intentionally
 *    not wired here.
 */
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { logWarn } from "../logger.js";

const GENESIS_PREV_HASH = "0".repeat(64);
const DEFAULT_LOG_PATH = path.join("logs", "audit-chain.ndjson");

export type AuditChainEntryInput = {
  entryId: string;
  approvalId?: string;
  toolName: string;
  argv: unknown;
  nonce?: string;
  timestamp?: number;
  logPath?: string;
};

export type AuditChainEntry = {
  entryId: string;
  approvalId?: string;
  toolName: string;
  argvHash: string;
  nonce?: string;
  timestamp: number;
  prevLogHash: string;
};

export type AuditChainVerifyResult = { ok: true } | { ok: false; brokenAt: number; reason: string };

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`);
  return `{${parts.join(",")}}`;
}

export function computeArgvHash(argv: unknown): string {
  return sha256Hex(canonicalize(argv));
}

function serializeEntry(entry: AuditChainEntry): string {
  const ordered: Record<string, unknown> = {
    entryId: entry.entryId,
    approvalId: entry.approvalId,
    toolName: entry.toolName,
    argvHash: entry.argvHash,
    nonce: entry.nonce,
    timestamp: entry.timestamp,
    prevLogHash: entry.prevLogHash,
  };
  return canonicalize(ordered);
}

function parseLine(line: string): AuditChainEntry | null {
  try {
    const parsed = JSON.parse(line) as Partial<AuditChainEntry>;
    if (
      typeof parsed.entryId !== "string" ||
      typeof parsed.toolName !== "string" ||
      typeof parsed.argvHash !== "string" ||
      typeof parsed.timestamp !== "number" ||
      typeof parsed.prevLogHash !== "string"
    ) {
      return null;
    }
    return {
      entryId: parsed.entryId,
      approvalId: parsed.approvalId,
      toolName: parsed.toolName,
      argvHash: parsed.argvHash,
      nonce: parsed.nonce,
      timestamp: parsed.timestamp,
      prevLogHash: parsed.prevLogHash,
    };
  } catch {
    return null;
  }
}

async function readLastLine(filePath: string): Promise<string | null> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    if (content.length === 0) return null;
    const trimmed = content.endsWith("\n") ? content.slice(0, -1) : content;
    if (trimmed.length === 0) return null;
    const newlineIdx = trimmed.lastIndexOf("\n");
    return newlineIdx === -1 ? trimmed : trimmed.slice(newlineIdx + 1);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

const writeQueues = new Map<string, Promise<void>>();

function enqueueAppend(filePath: string, work: () => Promise<void>): Promise<void> {
  const previous = writeQueues.get(filePath) ?? Promise.resolve();
  const next = previous.then(work, work);
  writeQueues.set(
    filePath,
    next.finally(() => {
      if (writeQueues.get(filePath) === next) writeQueues.delete(filePath);
    }),
  );
  return next;
}

async function resolvePrevHash(filePath: string): Promise<string> {
  const lastLine = await readLastLine(filePath);
  if (!lastLine) return GENESIS_PREV_HASH;
  return sha256Hex(lastLine);
}

export async function appendAuditEntry(input: AuditChainEntryInput): Promise<AuditChainEntry> {
  const filePath = path.resolve(input.logPath ?? DEFAULT_LOG_PATH);
  const argvHash = computeArgvHash(input.argv);
  const timestamp = input.timestamp ?? Date.now();
  let serialized = "";
  let result: AuditChainEntry | null = null;
  await enqueueAppend(filePath, async () => {
    const prevLogHash = await resolvePrevHash(filePath);
    const entry: AuditChainEntry = {
      entryId: input.entryId,
      approvalId: input.approvalId,
      toolName: input.toolName,
      argvHash,
      nonce: input.nonce,
      timestamp,
      prevLogHash,
    };
    serialized = serializeEntry(entry);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.appendFile(filePath, `${serialized}\n`, "utf8");
    result = entry;
  });
  if (!result) throw new Error("audit-chain: append produced no entry");
  return result;
}

export function tryAppendAuditEntry(input: AuditChainEntryInput): void {
  void appendAuditEntry(input).catch((err) => {
    logWarn(`audit-chain: append failed: ${String(err)}`);
  });
}

export async function verifyAuditChain(filePath: string): Promise<AuditChainVerifyResult> {
  let content: string;
  try {
    content = await fs.readFile(path.resolve(filePath), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ok: true };
    return { ok: false, brokenAt: 0, reason: `read failed: ${String(err)}` };
  }
  const trimmed = content.endsWith("\n") ? content.slice(0, -1) : content;
  if (trimmed.length === 0) return { ok: true };
  const lines = trimmed.split("\n");
  let expectedPrev = GENESIS_PREV_HASH;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const entry = parseLine(line);
    if (!entry) return { ok: false, brokenAt: i, reason: "malformed entry" };
    if (entry.prevLogHash !== expectedPrev) {
      return { ok: false, brokenAt: i, reason: "prevLogHash mismatch" };
    }
    if (entry.argvHash.length !== 64) {
      return { ok: false, brokenAt: i, reason: "argvHash malformed" };
    }
    expectedPrev = sha256Hex(line);
  }
  return { ok: true };
}

export const __AUDIT_CHAIN_INTERNALS = {
  GENESIS_PREV_HASH,
  DEFAULT_LOG_PATH,
};

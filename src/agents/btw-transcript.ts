import { readFile } from "node:fs/promises";
import {
  buildSessionContext,
  migrateSessionEntries,
  parseSessionEntries,
  type SessionEntry as PiSessionEntry,
} from "@earendil-works/pi-coding-agent";
import {
  resolveSessionFilePath,
  resolveSessionFilePathOptions,
  type SessionEntry as StoredSessionEntry,
} from "../config/sessions.js";
import { diagnosticLogger as diag } from "../logging/diagnostic.js";
import { purifyParsedTranscriptEntries } from "../security/context-purification.js";

export function resolveBtwSessionTranscriptPath(params: {
  sessionId: string;
  sessionEntry?: StoredSessionEntry;
  sessionKey?: string;
  storePath?: string;
}): string | undefined {
  try {
    const agentId = params.sessionKey?.split(":")[1];
    const pathOpts = resolveSessionFilePathOptions({
      agentId,
      storePath: params.storePath,
    });
    return resolveSessionFilePath(params.sessionId, params.sessionEntry, pathOpts);
  } catch (error) {
    diag.debug(
      `resolveSessionTranscriptPath failed: sessionId=${params.sessionId} err=${String(error)}`,
    );
    return undefined;
  }
}

function readSessionEntryId(entry: PiSessionEntry): string | undefined {
  const id = (entry as { id?: unknown }).id;
  return typeof id === "string" && id.trim().length > 0 ? id : undefined;
}

function readSessionEntryParentId(entry: PiSessionEntry): string | null | undefined {
  const parentId = (entry as { parentId?: unknown }).parentId;
  if (parentId === null) {
    return null;
  }
  return typeof parentId === "string" && parentId.trim().length > 0 ? parentId : undefined;
}

function hasParentLinkedEntries(entries: PiSessionEntry[]): boolean {
  return entries.some((entry) => Boolean(readSessionEntryId(entry) && "parentId" in entry));
}

function buildSessionBranchEntries(
  entries: PiSessionEntry[],
  leafId: string | undefined,
): PiSessionEntry[] | undefined {
  if (!leafId) {
    return undefined;
  }
  const byId = new Map<string, PiSessionEntry>();
  for (const entry of entries) {
    const id = readSessionEntryId(entry);
    if (id) {
      byId.set(id, entry);
    }
  }
  const branch: PiSessionEntry[] = [];
  const seen = new Set<string>();
  let currentId: string | undefined = leafId;
  while (currentId) {
    if (seen.has(currentId)) {
      return undefined;
    }
    seen.add(currentId);
    const entry = byId.get(currentId);
    if (!entry) {
      return undefined;
    }
    branch.push(entry);
    currentId = readSessionEntryParentId(entry) ?? undefined;
  }
  return branch.toReversed();
}

function readDefaultLeafId(entries: PiSessionEntry[]): string | undefined {
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const id = readSessionEntryId(entries[index]);
    if (id) {
      return id;
    }
  }
  return undefined;
}

function isTrailingUserMessage(entry: PiSessionEntry | undefined): boolean {
  return (
    entry?.type === "message" &&
    (entry as { message?: { role?: unknown } }).message?.role === "user"
  );
}

export async function readBtwTranscriptMessages(params: {
  sessionFile: string;
  sessionId: string;
  snapshotLeafId?: string | null;
  // D.3 — when set, the purifyParsedTranscriptEntries gate consults the
  // taint store + in-process touch signal for this correlation id; on
  // touch, the purifier rewrites entry content before buildSessionContext
  // turns entries into next-turn prompt messages. Callers without
  // prior-turn correlation context omit this and skip purification
  // (matches the existing behavior pre-D.3).
  priorCorrelationId?: string;
}): Promise<unknown[]> {
  try {
    const entries = parseSessionEntries(await readFile(params.sessionFile, "utf-8"));
    migrateSessionEntries(entries);
    const sessionEntries = entries.filter(
      (entry): entry is PiSessionEntry => entry.type !== "session",
    );
    const purifiedSessionEntries = await maybePurifySessionEntries(
      sessionEntries,
      params.priorCorrelationId,
      params.sessionId,
    );
    if (!hasParentLinkedEntries(purifiedSessionEntries)) {
      return buildSessionContext(purifiedSessionEntries).messages;
    }

    let branchEntries = params.snapshotLeafId
      ? buildSessionBranchEntries(purifiedSessionEntries, params.snapshotLeafId)
      : undefined;
    if (params.snapshotLeafId && !branchEntries) {
      diag.debug(
        `btw snapshot leaf unavailable: sessionId=${params.sessionId} leaf=${params.snapshotLeafId}`,
      );
    }
    branchEntries ??= buildSessionBranchEntries(
      purifiedSessionEntries,
      readDefaultLeafId(purifiedSessionEntries),
    );
    if (!params.snapshotLeafId && isTrailingUserMessage(branchEntries?.at(-1))) {
      const parentId = readSessionEntryParentId(branchEntries!.at(-1)!);
      branchEntries = parentId
        ? (buildSessionBranchEntries(purifiedSessionEntries, parentId) ?? [])
        : [];
    }
    const sessionContext = buildSessionContext(branchEntries ?? purifiedSessionEntries);
    return Array.isArray(sessionContext.messages) ? sessionContext.messages : [];
  } catch {
    return [];
  }
}

// D.3 — purification wire-up. Consults the gate via priorCorrelationId; on
// touch, rewrites the text content of each entry. Pi's SessionEntry shape
// is owned upstream and varies by entry type — for safe in-memory rewrite
// we round-trip each entry through JSON, replace its serialized form with
// the sanitized line, and re-parse. Entries whose post-rewrite shape no
// longer parses as JSON fall back to the original (fail-open per the
// purifier's defense-in-depth posture).
async function maybePurifySessionEntries(
  entries: PiSessionEntry[],
  priorCorrelationId: string | undefined,
  sessionId: string,
): Promise<PiSessionEntry[]> {
  if (!priorCorrelationId || entries.length === 0) {
    return entries;
  }
  const verdict = await purifyParsedTranscriptEntries<PiSessionEntry>({
    entries,
    priorCorrelationId,
    getContent: (entry) => JSON.stringify(entry),
    setContent: (original, sanitized) => {
      try {
        return JSON.parse(sanitized) as PiSessionEntry;
      } catch {
        return original;
      }
    },
  });
  if (!verdict.purified) {
    return entries;
  }
  diag.debug(
    `btw transcript purified: sessionId=${sessionId} corr=${priorCorrelationId} removed=${verdict.removedCount}`,
  );
  return verdict.entries;
}

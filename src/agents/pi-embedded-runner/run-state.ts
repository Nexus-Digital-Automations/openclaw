import type { SourceReplyDeliveryMode } from "../../auto-reply/get-reply-options.types.js";
import {
  getActiveReplyRunCount,
  listActiveReplyRunSessionKeys,
  listActiveReplyRunSessionIds,
} from "../../auto-reply/reply/reply-run-registry.js";
import { resolveGlobalSingleton } from "../../shared/global-singleton.js";

export type EmbeddedPiQueueHandle = {
  kind?: "embedded";
  queueMessage: (text: string, options?: EmbeddedPiQueueMessageOptions) => Promise<void>;
  isStreaming: () => boolean;
  isCompacting: () => boolean;
  supportsTranscriptCommitWait?: boolean;
  cancel?: (reason?: "user_abort" | "restart" | "superseded") => void;
  abort: () => void;
  sourceReplyDeliveryMode?: SourceReplyDeliveryMode;
};

export type EmbeddedPiQueueMessageOptions = {
  steeringMode?: "all";
  debounceMs?: number;
  deliveryTimeoutMs?: number;
  waitForTranscriptCommit?: boolean;
  sourceReplyDeliveryMode?: SourceReplyDeliveryMode;
};

export type ActiveEmbeddedRunSnapshot = {
  transcriptLeafId: string | null;
  messages?: unknown[];
  inFlightPrompt?: string;
};

export type EmbeddedRunModelSwitchRequest = {
  provider: string;
  model: string;
  authProfileId?: string;
  authProfileIdSource?: "auto" | "user";
};

export type EmbeddedRunWaiter = {
  resolve: (ended: boolean) => void;
  timer: NodeJS.Timeout;
};

const EMBEDDED_RUN_STATE_KEY = Symbol.for("openclaw.embeddedRunState");

const embeddedRunState = resolveGlobalSingleton(EMBEDDED_RUN_STATE_KEY, () => ({
  activeRuns: new Map<string, EmbeddedPiQueueHandle>(),
  snapshots: new Map<string, ActiveEmbeddedRunSnapshot>(),
  sessionIdsByKey: new Map<string, string>(),
  waiters: new Map<string, Set<EmbeddedRunWaiter>>(),
  modelSwitchRequests: new Map<string, EmbeddedRunModelSwitchRequest>(),
  // D-0 — per-session previous-turn correlationId, populated at turn-end so
  // the next turn's context-load can ask "was the previous turn tainted?"
  // without re-scanning the transcript. Process-restart resets it; the disk
  // taint store at logs/context-taint.ndjson provides the cross-restart
  // answer that the next turn's context-load consults via the consumer
  // helpers wired in D.7.
  priorRunCorrelationIdsBySession: new Map<string, string>(),
}));

export const ACTIVE_EMBEDDED_RUNS =
  embeddedRunState.activeRuns ??
  (embeddedRunState.activeRuns = new Map<string, EmbeddedPiQueueHandle>());
export const ACTIVE_EMBEDDED_RUN_SNAPSHOTS =
  embeddedRunState.snapshots ??
  (embeddedRunState.snapshots = new Map<string, ActiveEmbeddedRunSnapshot>());
export const ACTIVE_EMBEDDED_RUN_SESSION_IDS_BY_KEY =
  embeddedRunState.sessionIdsByKey ??
  (embeddedRunState.sessionIdsByKey = new Map<string, string>());
export const EMBEDDED_RUN_WAITERS =
  embeddedRunState.waiters ??
  (embeddedRunState.waiters = new Map<string, Set<EmbeddedRunWaiter>>());
export const EMBEDDED_RUN_MODEL_SWITCH_REQUESTS =
  embeddedRunState.modelSwitchRequests ??
  (embeddedRunState.modelSwitchRequests = new Map<string, EmbeddedRunModelSwitchRequest>());
const PRIOR_RUN_CORRELATION_IDS_BY_SESSION =
  embeddedRunState.priorRunCorrelationIdsBySession ??
  (embeddedRunState.priorRunCorrelationIdsBySession = new Map<string, string>());

export function getPriorRunCorrelationId(sessionId: string): string | undefined {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return undefined;
  }
  return PRIOR_RUN_CORRELATION_IDS_BY_SESSION.get(sessionId);
}

export function setPriorRunCorrelationId(sessionId: string, correlationId: string): void {
  if (
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    typeof correlationId !== "string" ||
    correlationId.length === 0
  ) {
    return;
  }
  PRIOR_RUN_CORRELATION_IDS_BY_SESSION.set(sessionId, correlationId);
}

export function clearPriorRunCorrelationIdsForTests(): void {
  PRIOR_RUN_CORRELATION_IDS_BY_SESSION.clear();
}

export function getActiveEmbeddedRunCount(): number {
  let activeCount = ACTIVE_EMBEDDED_RUNS.size;
  for (const sessionId of listActiveReplyRunSessionIds()) {
    if (!ACTIVE_EMBEDDED_RUNS.has(sessionId)) {
      activeCount += 1;
    }
  }
  return Math.max(activeCount, getActiveReplyRunCount());
}

export function listActiveEmbeddedRunSessionKeys(): string[] {
  return [
    ...new Set([
      ...ACTIVE_EMBEDDED_RUN_SESSION_IDS_BY_KEY.keys(),
      ...listActiveReplyRunSessionKeys(),
    ]),
  ].toSorted((a, b) => a.localeCompare(b));
}

export function listActiveEmbeddedRunSessionIds(): string[] {
  return [
    ...new Set([
      ...ACTIVE_EMBEDDED_RUNS.keys(),
      ...ACTIVE_EMBEDDED_RUN_SESSION_IDS_BY_KEY.values(),
      ...listActiveReplyRunSessionIds(),
    ]),
  ].toSorted((a, b) => a.localeCompare(b));
}

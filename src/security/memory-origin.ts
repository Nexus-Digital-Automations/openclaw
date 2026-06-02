/**
 * Owner: security/memory-origin.
 *
 * C.2 / C.3 / 1.E — memory taint integration primitive. Bridges the
 * workspace-zones classifier (already shipped in 1.B) to the new
 * `origin` field on MemoryChunk / MemorySearchResult that landed in
 * C.1. Memory writers call `originForAbsolutePath` at chunk-construction
 * time; retrievers call `wrapUntrustedSnippetIfNeeded` before joining
 * snippets into the system prompt.
 *
 * Threat model: a poisoned file dropped into the untrusted zone (e.g.
 * `~/.openclaw/untrusted/...`) gets indexed into memory like any other
 * source. Without taint tracking, on retrieval that content gets joined
 * verbatim into the prompt and the model treats it as authoritative.
 * Tagging the chunk's origin at write time + wrapping it in
 * external-content markers + canary at retrieval time gives the model
 * the structural cue that this snippet is data, not instruction, and
 * makes the firewall trip if the model echoes a canary back.
 *
 * @stable
 */

import {
  classifyZone,
  type WorkspaceZone,
  type WorkspaceZoneOptions,
} from "../agents/workspace-zones.js";
import { wrapExternalContent } from "./external-content.js";

export type MemoryChunkOrigin = "trusted" | "untrusted";

/**
 * Classify the origin of a memory chunk being indexed from an absolute
 * path. Pure function over the workspace-zones classifier — the chunk
 * inherits its origin from the file zone:
 *
 *   trusted-zone path  → "trusted"
 *   untrusted-zone path → "untrusted"
 *
 * The contract is intentionally tighter than `WorkspaceZone` (which has
 * more zone kinds): memory-origin collapses every non-untrusted zone
 * to "trusted" so retrievers branch on a binary discriminant.
 *
 * @stable
 */
export function originForAbsolutePath(
  absolutePath: string,
  options?: WorkspaceZoneOptions,
): MemoryChunkOrigin {
  const zone: WorkspaceZone = classifyZone(absolutePath, options);
  return zone === "untrusted" ? "untrusted" : "trusted";
}

/**
 * Wrap a memory snippet's text in the external-content sandwich + canary
 * iff the chunk's origin is "untrusted". Trusted snippets pass through
 * unchanged so prompt-cache identity is preserved on the hot path.
 *
 * Memory chunks ingested from the untrusted zone use the
 * `untrusted_zone` ExternalContentSource value — that's the canonical
 * label the wrap's `Source:` metadata line already understands. Callers
 * may additionally pass a `subject` (for example the chunk's file path)
 * so forensic logs can trace the origin file.
 *
 * @stable
 */
export function wrapUntrustedSnippetIfNeeded(
  text: string,
  origin: MemoryChunkOrigin | undefined,
  forensicSubject?: string,
): string {
  if (origin !== "untrusted") {
    return text;
  }
  return wrapExternalContent(text, {
    source: "untrusted_zone",
    ...(forensicSubject ? { subject: forensicSubject } : {}),
  });
}

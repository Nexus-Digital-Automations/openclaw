// Owner: plugins/builtin-security-sandwich.
//
// Outbound-leak detector. Given a string the agent is about to send on a
// channel, scan it for:
//   - resolved-secret literals (process-wide registry from secrets/resolve.ts)
//   - external-content canaries (`OPENCLAW_CANARY_<hex>` — the literal that
//     external-content wrappers tell the model never to echo)
//
// Returns either { safe: true, content } when nothing matched, or
// { safe: false, redacted, reason } when a hit was redacted. The plugin's
// message_sending hook converts the unsafe variant into a `cancel: true`
// result with the redacted content as the replacement body.
//
// `OPENCLAW_CANARY_` is a literal prefix emitted by external-content
// wrapping (`src/security/external-content.ts`). Matching by prefix avoids
// taking a runtime dep on a canary registry that may not be populated when
// the hook runs (e.g. when a canary was seeded in a different process).

import { snapshotExternalContentBodies } from "../../shared/process-external-content-bodies.js";
import { snapshotResolvedSecrets } from "../../shared/process-secret-literals.js";

const CANARY_LITERAL_PATTERN = /OPENCLAW_CANARY_[0-9a-f]{8,}/g;
const REDACTION_PLACEHOLDER = "[REDACTED]";

export type OutboundScanSafeResult = {
  safe: true;
  content: string;
};

export type OutboundScanUnsafeResult = {
  safe: false;
  redacted: string;
  reason: string;
};

export type OutboundScanResult = OutboundScanSafeResult | OutboundScanUnsafeResult;

/**
 * Scan an outbound message body for unredacted secrets or canaries.
 *
 * Failure modes: returns an unsafe result; never throws. The caller (the
 * message_sending hook) treats unsafe as `cancel: true` so the operator is
 * notified rather than silently shipping the masked variant.
 *
 * @stable
 */
export function scanOutboundContent(content: string): OutboundScanResult {
  if (typeof content !== "string" || content.length === 0) {
    return { safe: true, content };
  }

  const hits: string[] = [];
  let redacted = content;

  const secretHits = redactSecretLiterals(redacted);
  redacted = secretHits.text;
  if (secretHits.matched.length > 0) {
    hits.push(`secret(${secretHits.matched.length})`);
  }

  const canaryHits = redactCanaries(redacted);
  redacted = canaryHits.text;
  if (canaryHits.matched.length > 0) {
    hits.push(`canary(${canaryHits.matched.length})`);
  }

  if (hits.length === 0) {
    return { safe: true, content };
  }
  return {
    safe: false,
    redacted,
    reason: `outbound contains unredacted ${hits.join(",")}`,
  };
}

type RedactionPass = {
  text: string;
  matched: string[];
};

function redactSecretLiterals(text: string): RedactionPass {
  const secrets = snapshotResolvedSecrets();
  const externalBodies = snapshotExternalContentBodies();
  const candidates = [...secrets, ...externalBodies];
  if (candidates.length === 0) {
    return { text, matched: [] };
  }

  let next = text;
  const matched: string[] = [];
  // Longest-first so a long secret that contains a shorter literal is masked
  // intact rather than getting partially-replaced and leaving fragments.
  const ordered = [...candidates].sort((left, right) => right.length - left.length);
  for (const literal of ordered) {
    if (literal.length < 4) {
      continue;
    }
    if (next.includes(literal)) {
      matched.push(literal);
      next = splitJoinReplace(next, literal, REDACTION_PLACEHOLDER);
    }
  }
  return { text: next, matched };
}

function redactCanaries(text: string): RedactionPass {
  const matched = text.match(CANARY_LITERAL_PATTERN);
  if (!matched || matched.length === 0) {
    return { text, matched: [] };
  }
  return {
    text: text.replace(CANARY_LITERAL_PATTERN, REDACTION_PLACEHOLDER),
    matched: [...matched],
  };
}

// String.replaceAll on a literal would require re-escaping per RegExp; the
// split/join form is constant-cost and avoids any regex-injection risk.
function splitJoinReplace(text: string, needle: string, replacement: string): string {
  return text.split(needle).join(replacement);
}

/**
 * Owner: P1.8 internal-judge LLM surface — non-interactive, JSON-schema
 * constrained, no-tool-use model invocation reused by security features
 * (plugin install audit, asymmetric trust split, context purifier).
 *
 * Foundational primitive only. Does not wire itself into install paths,
 * agent runtime, or any CLI command. Other security modules call this
 * library and consume the discriminated return shape.
 *
 * State diagram (per call):
 *
 *   request --> wrap untrusted fields --> build prompt --> provider call
 *     timeout -> { ok: false, reason: "timeout" }
 *     HTTP / network error -> { ok: false, reason: "model_error" }
 *     plain-text refusal -> { ok: false, reason: "refused" }
 *     non-JSON body -> { ok: false, reason: "schema_violation" }
 *     JSON fails ajv validation -> { ok: false, reason: "schema_violation" }
 *     valid JSON output -> { ok: true, output, modelId, tokens, latencyMs }
 *
 * SECURITY: every field listed in `untrustedFields` is wrapped with the
 * sandwich-pattern external-content markers from
 * `src/security/external-content.ts` before serialization, so prompt-injection
 * attempts inside audited code cannot masquerade as judge instructions. The
 * judge model has zero tool surface.
 */
import AjvPkg, { type AnySchema, type ValidateFunction } from "ajv";
import { redactSensitiveText } from "../logging/redact.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { wrapExternalContent } from "../security/external-content.js";
import { buildAnthropicJudgeProvider, type JudgeProvider } from "./internal-judge-providers.js";

type AjvInstance = import("ajv").default;
const AjvCtor = AjvPkg as unknown as { new (opts?: object): AjvInstance };

export type JudgeJsonSchema = AnySchema;

export type JudgeRequest<TInput extends Record<string, unknown>, _TOutput> = {
  role: string;
  systemPrompt: string;
  userPayload: TInput;
  untrustedFields: ReadonlyArray<keyof TInput & string>;
  responseSchema: JudgeJsonSchema;
  modelHint?: "fast" | "accurate";
  timeoutMs?: number;
};

export type JudgeFailureReason = "schema_violation" | "timeout" | "model_error" | "refused";

export type JudgeResponse<TOutput> =
  | {
      ok: true;
      output: TOutput;
      modelId: string;
      inputTokens: number;
      outputTokens: number;
      latencyMs: number;
    }
  | { ok: false; reason: JudgeFailureReason; detail: string };

export type JudgeRuntime = {
  provider?: JudgeProvider;
  now?: () => number;
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_TOKENS = 2048;
// WHY: Haiku-tier model for `fast`, Sonnet-tier for `accurate`. Matches the
// upgrade map in `extensions/anthropic/claude-model-refs.ts`. Overridable
// via env so operators can pin a cheaper / newer judge model without code
// change.
const DEFAULT_MODEL_FAST = "claude-haiku-4-5";
const DEFAULT_MODEL_ACCURATE = "claude-sonnet-4-6";

const judgeLog = createSubsystemLogger("internal-judge");
const ajv = new AjvCtor({ allErrors: false, strict: false });
const validatorCache = new WeakMap<JudgeJsonSchema, ValidateFunction>();

function compileValidator(schema: JudgeJsonSchema): ValidateFunction {
  const cached = validatorCache.get(schema);
  if (cached) {
    return cached;
  }
  const validate = ajv.compile(schema);
  validatorCache.set(schema, validate);
  return validate;
}

function resolveModelId(hint: "fast" | "accurate" | undefined): string {
  const effective = hint ?? "fast";
  if (effective === "accurate") {
    return process.env.OPENCLAW_JUDGE_MODEL_ACCURATE || DEFAULT_MODEL_ACCURATE;
  }
  return process.env.OPENCLAW_JUDGE_MODEL_FAST || DEFAULT_MODEL_FAST;
}

function resolveProvider(): JudgeProvider {
  // WHY: Only Anthropic is wired today. Adding OpenAI later means a new case
  // here keyed off OPENCLAW_JUDGE_PROVIDER. Default stays Anthropic so a
  // missing env var does not silently switch judge backends.
  const providerId = (process.env.OPENCLAW_JUDGE_PROVIDER || "anthropic").toLowerCase();
  if (providerId !== "anthropic") {
    throw new Error(`unsupported OPENCLAW_JUDGE_PROVIDER: ${providerId}`);
  }
  return buildAnthropicJudgeProvider();
}

function serializeFieldValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function buildUntrustedSection<TInput extends Record<string, unknown>>(
  payload: TInput,
  untrustedFields: ReadonlyArray<keyof TInput & string>,
): string {
  if (untrustedFields.length === 0) {
    return "";
  }
  const sections: string[] = [];
  for (const field of untrustedFields) {
    const wrapped = wrapExternalContent(serializeFieldValue(payload[field]), {
      source: "untrusted_zone",
      subject: `judge.userPayload.${field}`,
      includeWarning: true,
    });
    sections.push(`Field "${field}":\n${wrapped}`);
  }
  return sections.join("\n\n");
}

function buildTrustedSection<TInput extends Record<string, unknown>>(
  payload: TInput,
  untrustedFields: ReadonlyArray<keyof TInput & string>,
): string {
  const untrustedSet = new Set<string>(untrustedFields);
  const trusted: Record<string, unknown> = {};
  for (const key of Object.keys(payload)) {
    if (!untrustedSet.has(key)) {
      trusted[key] = payload[key];
    }
  }
  if (Object.keys(trusted).length === 0) {
    return "";
  }
  return `Trusted inputs:\n${JSON.stringify(trusted, null, 2)}`;
}

function buildJudgeUserPrompt<TInput extends Record<string, unknown>>(
  req: JudgeRequest<TInput, unknown>,
): string {
  const trusted = buildTrustedSection(req.userPayload, req.untrustedFields);
  const untrusted = buildUntrustedSection(req.userPayload, req.untrustedFields);
  const schemaBlock =
    "Respond with ONLY a single JSON object matching this JSON schema. " +
    `No prose, no code fences:\n${JSON.stringify(req.responseSchema)}`;
  return [trusted, untrusted, schemaBlock].filter((s) => s.length > 0).join("\n\n");
}

const REFUSAL_PATTERNS = [
  /^\s*i\s+(?:can(?:'|no)t|will\s+not|am\s+unable\s+to)\b/i,
  /^\s*sorry[,.]?\s+(?:i|but)\b/i,
  /^\s*as\s+an?\s+ai\b/i,
  /\bI\s+(?:cannot|won't|will\s+not)\s+(?:help|comply|assist)\b/i,
];

function detectPlainTextRefusal(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) {
    return false;
  }
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return false;
  }
  return REFUSAL_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function tryParseJudgeJson(text: string): { ok: true; value: unknown } | { ok: false } {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false };
  }
  try {
    return { ok: true, value: JSON.parse(trimmed) };
  } catch {
    // WHY: models sometimes wrap JSON in ```json fences despite the
    // instruction. One narrow recovery attempt; otherwise schema_violation.
    const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
    if (!fence) {
      return { ok: false };
    }
    try {
      return { ok: true, value: JSON.parse(fence[1] ?? "") };
    } catch {
      return { ok: false };
    }
  }
}

function logRequestEvent(role: string, modelId: string, timeoutMs: number): void {
  judgeLog.info("internal_judge.request", {
    role: redactSensitiveText(role),
    modelId,
    timeoutMs,
  });
}

function logResponseEvent<TOutput>(
  role: string,
  modelId: string,
  result: JudgeResponse<TOutput>,
): void {
  if (result.ok) {
    judgeLog.info("internal_judge.response", {
      role: redactSensitiveText(role),
      modelId,
      outcome: "ok",
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      latencyMs: result.latencyMs,
    });
    return;
  }
  judgeLog.warn("internal_judge.response", {
    role: redactSensitiveText(role),
    modelId,
    outcome: result.reason,
    detail: redactSensitiveText(result.detail).slice(0, 300),
  });
}

/**
 * Invoke the internal judge model with a constrained-JSON response contract.
 *
 * Failure modes returned in the discriminated-union shape (does not throw):
 * - `timeout`: provider did not return within `timeoutMs`.
 * - `model_error`: HTTP / network / provider error.
 * - `refused`: provider returned a plain-text refusal instead of JSON.
 * - `schema_violation`: response was not valid JSON or did not match
 *   `responseSchema` per ajv compilation.
 *
 * @stable
 */
export async function invokeInternalJudge<TInput extends Record<string, unknown>, TOutput>(
  req: JudgeRequest<TInput, TOutput>,
  runtime?: JudgeRuntime,
): Promise<JudgeResponse<TOutput>> {
  const modelId = resolveModelId(req.modelHint);
  const timeoutMs = req.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const now = runtime?.now ?? Date.now;
  const provider = runtime?.provider ?? resolveProvider();
  const userPrompt = buildJudgeUserPrompt(req);
  logRequestEvent(req.role, modelId, timeoutMs);
  const started = now();
  const providerResult = await provider({
    model: modelId,
    systemPrompt: req.systemPrompt,
    userPrompt,
    maxTokens: DEFAULT_MAX_OUTPUT_TOKENS,
    timeoutMs,
  });
  const latencyMs = now() - started;
  const finalized = finalizeProviderResult<TOutput>(req, providerResult, latencyMs);
  logResponseEvent(req.role, modelId, finalized);
  return finalized;
}

function finalizeProviderResult<TOutput>(
  req: JudgeRequest<Record<string, unknown>, TOutput>,
  providerResult: Awaited<ReturnType<JudgeProvider>>,
  latencyMs: number,
): JudgeResponse<TOutput> {
  if (providerResult.kind === "timeout") {
    return {
      ok: false,
      reason: "timeout",
      detail: `judge exceeded ${req.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`,
    };
  }
  if (providerResult.kind === "model_error") {
    return { ok: false, reason: "model_error", detail: providerResult.detail };
  }
  if (detectPlainTextRefusal(providerResult.text)) {
    return { ok: false, reason: "refused", detail: providerResult.text.slice(0, 200) };
  }
  const parsed = tryParseJudgeJson(providerResult.text);
  if (!parsed.ok) {
    return { ok: false, reason: "schema_violation", detail: "response was not valid JSON" };
  }
  const validate = compileValidator(req.responseSchema);
  if (!validate(parsed.value)) {
    return {
      ok: false,
      reason: "schema_violation",
      detail: ajv.errorsText(validate.errors, { separator: "; " }),
    };
  }
  return {
    ok: true,
    output: parsed.value as TOutput,
    modelId: providerResult.modelId,
    inputTokens: providerResult.inputTokens,
    outputTokens: providerResult.outputTokens,
    latencyMs,
  };
}

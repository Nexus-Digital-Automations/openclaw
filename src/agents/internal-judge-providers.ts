/**
 * Owner: P1.8 internal-judge surface (`internal-judge.ts`).
 *
 * Minimal non-streaming provider adapter for `invokeInternalJudge`. Kept small
 * and one-shot on purpose: the judge has no tool-use, no SSE, no replay
 * policies, and no auth-profile rotation. If a future judge consumer needs
 * those, route it through the normal agent transport instead of growing this
 * module into a parallel transport.
 *
 * State diagram (per call):
 *
 *   request --> fetch --> { non-2xx -> model_error,
 *                           timeout -> timeout,
 *                           abort   -> timeout,
 *                           2xx -> parse -> { ok | model_error } }
 */
import { setTimeout as setTimer, clearTimeout as clearTimer } from "node:timers";

export type JudgeProviderRequest = {
  model: string;
  systemPrompt: string;
  userPrompt: string;
  maxTokens: number;
  timeoutMs: number;
};

export type JudgeProviderResult =
  | { kind: "ok"; text: string; modelId: string; inputTokens: number; outputTokens: number }
  | { kind: "timeout" }
  | { kind: "model_error"; detail: string };

export type JudgeProvider = (req: JudgeProviderRequest) => Promise<JudgeProviderResult>;

// The Anthropic Messages API non-streaming response shape we depend on. Only
// the fields the judge actually reads are listed; provider may include more.
type AnthropicMessagesResponse = {
  model?: string;
  content?: Array<{ type: string; text?: string }>;
  usage?: { input_tokens?: number; output_tokens?: number };
  stop_reason?: string;
};

const ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com";

function resolveAnthropicMessagesUrl(): string {
  const base = (process.env.OPENCLAW_JUDGE_BASE_URL || ANTHROPIC_DEFAULT_BASE_URL).replace(
    /\/+$/,
    "",
  );
  return base.endsWith("/v1") ? `${base}/messages` : `${base}/v1/messages`;
}

function extractTextFromAnthropicBody(body: AnthropicMessagesResponse): string {
  if (!Array.isArray(body.content)) {
    return "";
  }
  const parts: string[] = [];
  for (const block of body.content) {
    if (block?.type === "text" && typeof block.text === "string") {
      parts.push(block.text);
    }
  }
  return parts.join("");
}

export function buildAnthropicJudgeProvider(deps?: {
  apiKey?: string;
  fetchImpl?: typeof fetch;
}): JudgeProvider {
  // Resolve the api key at call time so a test that sets the env var after
  // module import still picks it up. The provider closure stays cheap.
  const fetchImpl = deps?.fetchImpl ?? fetch;
  return async (req) => {
    const apiKey = deps?.apiKey ?? process.env.ANTHROPIC_API_KEY ?? "";
    if (!apiKey) {
      return { kind: "model_error", detail: "missing ANTHROPIC_API_KEY for internal judge" };
    }
    const controller = new AbortController();
    const timer = setTimer(() => controller.abort(), req.timeoutMs);
    try {
      const response = await fetchImpl(resolveAnthropicMessagesUrl(), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "anthropic-version": "2023-06-01",
          "x-api-key": apiKey,
        },
        body: JSON.stringify({
          model: req.model,
          max_tokens: req.maxTokens,
          system: req.systemPrompt,
          messages: [{ role: "user", content: req.userPrompt }],
        }),
        signal: controller.signal,
      });
      if (!response.ok) {
        const detail = await response.text().catch(() => "");
        return {
          kind: "model_error",
          detail: detail || `HTTP ${response.status}`,
        };
      }
      const body = (await response.json()) as AnthropicMessagesResponse;
      const text = extractTextFromAnthropicBody(body);
      return {
        kind: "ok",
        text,
        modelId: body.model ?? req.model,
        inputTokens: body.usage?.input_tokens ?? 0,
        outputTokens: body.usage?.output_tokens ?? 0,
      };
    } catch (err) {
      if (controller.signal.aborted) {
        return { kind: "timeout" };
      }
      const detail = err instanceof Error ? err.message : String(err);
      return { kind: "model_error", detail };
    } finally {
      clearTimer(timer);
    }
  };
}

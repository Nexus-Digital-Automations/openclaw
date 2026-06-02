/**
 * Owner: P1.8 internal-judge tracer-code demo. Not wired anywhere. Purely
 * demonstrates the surface other security features (plugin install audit,
 * trust split, context purifier) will consume. Typechecks but is never
 * imported by runtime code.
 *
 * @internal
 */
import { invokeInternalJudge, type JudgeJsonSchema } from "./internal-judge.js";

type IntentInput = { commandText: string };
type IntentOutput = { intent: "read" | "write" | "destructive"; confidence: number };

const intentSchema: JudgeJsonSchema = {
  type: "object",
  properties: {
    intent: { type: "string", enum: ["read", "write", "destructive"] },
    confidence: { type: "number", minimum: 0, maximum: 1 },
  },
  required: ["intent", "confidence"],
  additionalProperties: false,
};

export async function classifyShellIntent(commandText: string) {
  return invokeInternalJudge<IntentInput, IntentOutput>({
    role: "shell-intent-classifier",
    systemPrompt: "Classify the shell command intent. Reply JSON only.",
    userPayload: { commandText },
    untrustedFields: ["commandText"],
    responseSchema: intentSchema,
    modelHint: "fast",
  });
}

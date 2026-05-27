import { normalizeOptionalString } from "../../shared/string-coerce.js";
import {
  ErrorCodes,
  errorShape,
  formatValidationErrors,
  validateToolsInvokeParams,
  type ToolsInvokeResult,
} from "../protocol/index.js";
import { invokeGatewayTool } from "../tools-invoke-shared.js";
import type { GatewayRequestHandlers } from "./types.js";

function resolveRpcErrorCode(params: {
  type:
    | "invalid_request"
    | "not_found"
    | "tool_call_blocked"
    | "tool_error"
    | "verified_cmd_failure";
  requiresApproval?: boolean;
  // P1.1 fine-grained code from invokeGatewayTool (verified_cmd.*); when
  // present we surface it directly so callers can distinguish missing nonce
  // from chain break.
  code?: string;
}): string {
  if (params.requiresApproval) {
    return "requires_approval";
  }
  switch (params.type) {
    case "invalid_request":
      return "validation_error";
    case "not_found":
      return "not_found";
    case "tool_call_blocked":
      return "forbidden";
    case "tool_error":
      return "internal_error";
    case "verified_cmd_failure":
      return params.code ?? "forbidden";
  }
  return "internal_error";
}

export const toolsInvokeHandlers: GatewayRequestHandlers = {
  "tools.invoke": async ({ params, respond, context }) => {
    if (!validateToolsInvokeParams(params)) {
      respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.INVALID_REQUEST,
          `invalid tools.invoke params: ${formatValidationErrors(validateToolsInvokeParams.errors)}`,
        ),
      );
      return;
    }
    const requestedToolName = normalizeOptionalString(params.name);
    if (!requestedToolName) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "invalid tools.invoke params: name required"),
      );
      return;
    }

    const outcome = await invokeGatewayTool({
      cfg: context.getRuntimeConfig(),
      input: params,
      toolCallIdPrefix: "rpc",
      approvalMode: params.confirm === true ? "request" : "report",
    });

    if (outcome.ok) {
      const payload: ToolsInvokeResult = {
        ok: true,
        toolName: outcome.toolName,
        output: outcome.result,
        source: outcome.source,
      };
      respond(true, payload, undefined);
      return;
    }

    const payload: ToolsInvokeResult = {
      ok: false,
      toolName: outcome.toolName || requestedToolName,
      ...(outcome.error.requiresApproval ? { requiresApproval: true } : {}),
      error: {
        code: resolveRpcErrorCode(outcome.error),
        message: outcome.error.message,
      },
    };
    respond(true, payload, undefined);
  },
};

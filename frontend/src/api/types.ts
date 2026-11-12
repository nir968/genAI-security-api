// Response shapes of the gateway (gateway/main.py). Keep in sync by hand.

export const ACTIONS = ['allow', 'alert', 'redact', 'block'] as const;
export type Action = (typeof ACTIONS)[number];

export const DIRECTIONS = ['input', 'output'] as const;
export type Direction = (typeof DIRECTIONS)[number];

// gateway/dlp/models.py DATA_TYPES. The gateway sends plain strings, so the
// wire type stays `string`; this list is only used for display and sample data.
export const KNOWN_DATA_TYPES = [
  'CREDIT_CARD',
  'IL_ID',
  'IBAN',
  'EMAIL',
  'PHONE_IL',
  'AWS_ACCESS_KEY',
  'GITHUB_TOKEN',
  'PRIVATE_KEY',
  'JWT',
  'CREDENTIAL_ASSIGNMENT',
  'HIGH_ENTROPY_SECRET',
] as const;

/** GET /health */
export interface HealthResponse {
  status: string;
}

/** GET /stats */
export interface StatsResponse {
  total_requests: number;
  blocked_injections: number;
  data_leaks_prevented: number;
  redactions: number;
  alerts: number;
  status: string;
}

/** One element of GET /history -> records */
export interface HistoryRecord {
  /** ISO 8601, UTC, with a trailing "Z" */
  timestamp: string;
  blocked: boolean;
  threat_type: string;
  risk_score: number;
  /** already masked by the gateway when the DLP engine found something */
  prompt: string;
  action: Action;
  direction: Direction;
  data_types: string[];
}

/** GET /history */
export interface HistoryResponse {
  records: HistoryRecord[];
}

/** POST /inspect, 200, nothing sensitive or only alerts */
export interface InspectAllowedResponse {
  status: 'Allowed';
  risk_score: number;
  message: string;
  /** present only when the policy action was "alert" */
  alerts?: string[];
}

/** POST /inspect, 200, the policy action was "redact" */
export interface InspectRedactedResponse {
  status: 'Redacted';
  risk_score: number;
  redacted_prompt: string;
  data_types: string[];
}

export type InspectResponse = InspectAllowedResponse | InspectRedactedResponse;

/** `detail` of a 403 from /inspect or /chat. Note: no risk score. */
export interface InspectBlockedDetail {
  error: string;
  /** "Prompt Injection" or "DLP Violation" */
  threat: string;
  /** only for DLP blocks */
  data_types?: string[];
}

/** `detail` of a 413 */
export interface TooLongDetail {
  error: string;
  max_chars: number;
}

/** POST /chat, 200 */
export interface ChatResponse {
  response: string;
  input_action: Action;
  output_action: Action;
  data_types: {
    input: string[];
    output: string[];
  };
}

/** What the Playground gets back: a 403 is a normal outcome, not an error. */
export interface Blocked {
  kind: 'blocked';
  detail: InspectBlockedDetail;
}

export type InspectResult = { kind: 'ok'; data: InspectResponse } | Blocked;
export type ChatResult = { kind: 'ok'; data: ChatResponse } | Blocked;

// --- agent security (gateway/mcp_security.py) ---------------------------------

// gateway/mcp_security.py EVENT_TYPES. The gateway rejects anything else on write.
export const MCP_EVENT_TYPES = [
  'TOOL_CALL_ALLOWED',
  'TOOL_NOT_ALLOWED',
  'ARGS_DLP_BLOCKED',
  'ARGS_DLP_REDACTED',
  'RESULT_REDACTED',
  'RESULT_INJECTION_REMOVED',
  'TOOL_POISONING_SUSPECTED',
  'TOOL_DEFINITION_CHANGED',
  'APPROVAL_REQUESTED',
  'APPROVAL_GRANTED',
  'APPROVAL_DENIED',
  'APPROVAL_EXPIRED',
  'GATEWAY_UNAVAILABLE',
] as const;
export type McpEventType = (typeof MCP_EVENT_TYPES)[number];

export const MCP_DECISIONS = ['allow', 'deny', 'redact', 'sanitize', 'quarantine', 'pending'] as const;
export type McpDecision = (typeof MCP_DECISIONS)[number];

/** One element of GET /mcp/events -> events */
export interface McpEvent {
  id: number;
  /** ISO 8601, UTC, with a trailing "Z" */
  timestamp: string;
  event_type: McpEventType;
  server_name: string;
  /** null for events that are not about one tool */
  tool_name: string | null;
  decision: McpDecision;
  risk_score: number;
  data_types: string[];
  /** masked text; may be empty */
  details: string;
}

/** GET /mcp/events */
export interface McpEventsResponse {
  events: McpEvent[];
}

/** GET /mcp/stats. Counts cover all time, not a window. */
export interface McpStats {
  total_events: number;
  /** every known event type is present; unknown keys are possible, so index defensively */
  by_event_type: Record<string, number>;
  by_decision: Record<string, number>;
  pending_approvals: number;
}

export const APPROVAL_STATUSES = ['pending', 'approved', 'denied', 'expired'] as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];

/** One approval request, as returned by GET /mcp/approvals and the decision endpoint. */
export interface McpApproval {
  id: string;
  created_at: string;
  expires_at: string;
  server_name: string;
  tool_name: string;
  /** masked, usually JSON text; invisible characters are written as <U+XXXX> */
  args_masked: string;
  args_sha256: string;
  reason: string;
  status: ApprovalStatus;
  /** null while pending, and for approvals that expired without a decision */
  decided_at: string | null;
}

/** GET /mcp/approvals */
export interface McpApprovalsResponse {
  approvals: McpApproval[];
}

export type ApprovalDecision = 'approve' | 'deny';

/** POST /mcp/approvals/{id}/decision, request body */
export interface DecisionRequest {
  decision: ApprovalDecision;
}

/** What the UI gets back: a 409 is a normal outcome, not an error. */
export type DecisionResult =
  | { kind: 'ok'; approval: McpApproval }
  /** 409: already decided, or expired. `status` is what the gateway says it is now. */
  | { kind: 'conflict'; status: ApprovalStatus | null };

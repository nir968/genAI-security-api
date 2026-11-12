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

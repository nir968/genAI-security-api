import type {
  ApprovalDecision,
  ApprovalStatus,
  ChatResponse,
  ChatResult,
  DecisionRequest,
  DecisionResult,
  HealthResponse,
  HistoryResponse,
  InspectBlockedDetail,
  InspectResponse,
  InspectResult,
  McpApproval,
  McpApprovalsResponse,
  McpEventsResponse,
  McpStats,
  StatsResponse,
} from './types';

export const API_BASE = '/api';

/** Any failed request. status 0 means the gateway could not be reached. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown, message?: string) {
    super(message ?? `Request failed with status ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Narrow the `detail` of a 403 response. */
export function isBlockedDetail(value: unknown): value is InspectBlockedDetail {
  return (
    isRecord(value) &&
    typeof value.threat === 'string' &&
    typeof value.error === 'string' &&
    (value.data_types === undefined ||
      (Array.isArray(value.data_types) &&
        value.data_types.every((t) => typeof t === 'string')))
  );
}

interface RawResponse {
  status: number;
  ok: boolean;
  body: unknown;
}

async function send(path: string, init?: RequestInit): Promise<RawResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(0, null, 'Cannot reach the gateway');
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // an empty or non-JSON body (e.g. a proxy error page): keep null
  }
  return { status: response.status, ok: response.ok, body };
}

/** FastAPI wraps error payloads as { detail: ... }. */
function detailOf(body: unknown): unknown {
  return isRecord(body) && 'detail' in body ? body.detail : body;
}

function failure(raw: RawResponse): ApiError {
  return new ApiError(raw.status, detailOf(raw.body));
}

async function getJson<T>(path: string): Promise<T> {
  const raw = await send(path);
  if (!raw.ok) throw failure(raw);
  return raw.body as T;
}

function postJson(path: string, payload: unknown): Promise<RawResponse> {
  return send(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export const getHealth = () => getJson<HealthResponse>('/health');
export const getStats = () => getJson<StatsResponse>('/stats');
export const getHistory = (hours: number) =>
  getJson<HistoryResponse>(`/history?hours=${encodeURIComponent(String(hours))}`);

export async function inspectPrompt(prompt: string): Promise<InspectResult> {
  const raw = await postJson('/inspect', { prompt });
  if (raw.status === 403 && isBlockedDetail(detailOf(raw.body))) {
    return { kind: 'blocked', detail: detailOf(raw.body) as InspectBlockedDetail };
  }
  if (!raw.ok) throw failure(raw);
  return { kind: 'ok', data: raw.body as InspectResponse };
}

export async function sendChat(message: string): Promise<ChatResult> {
  const raw = await postJson('/chat', { message });
  if (raw.status === 403 && isBlockedDetail(detailOf(raw.body))) {
    return { kind: 'blocked', detail: detailOf(raw.body) as InspectBlockedDetail };
  }
  if (!raw.ok) throw failure(raw);
  return { kind: 'ok', data: raw.body as ChatResponse };
}

/** The most events one request asks for. The gateway allows up to 5000. */
export const MCP_EVENT_LIMIT = 2000;

export const getMcpEvents = (hours: number) =>
  getJson<McpEventsResponse>(
    `/mcp/events?hours=${encodeURIComponent(String(hours))}&limit=${MCP_EVENT_LIMIT}`,
  );
export const getMcpStats = () => getJson<McpStats>('/mcp/stats');

/** Without a status: every approval, pending ones included. */
export const getApprovals = (status?: ApprovalStatus) =>
  getJson<McpApprovalsResponse>(
    status === undefined ? '/mcp/approvals' : `/mcp/approvals?status=${encodeURIComponent(status)}`,
  );

function isApprovalStatus(value: unknown): value is ApprovalStatus {
  return value === 'pending' || value === 'approved' || value === 'denied' || value === 'expired';
}

export async function decideApproval(id: string, decision: ApprovalDecision): Promise<DecisionResult> {
  const payload: DecisionRequest = { decision };
  const raw = await postJson(`/mcp/approvals/${encodeURIComponent(id)}/decision`, payload);
  if (raw.status === 409) {
    const detail = detailOf(raw.body);
    const status = isRecord(detail) ? detail.status : undefined;
    return { kind: 'conflict', status: isApprovalStatus(status) ? status : null };
  }
  if (!raw.ok) throw failure(raw);
  return { kind: 'ok', approval: raw.body as McpApproval };
}

export const EXPORT_EXCEL_URL = `${API_BASE}/export-excel`;

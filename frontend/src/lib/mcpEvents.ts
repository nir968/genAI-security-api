import type { McpEvent, McpEventType, McpStats } from '../api/types';
import { RANGE_HOURS, type TimeRange } from './buckets';

export const EVENT_CATEGORIES = ['allowed', 'blocked', 'sanitized', 'poisoning', 'approval'] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

export const CATEGORY_LABELS: Record<EventCategory, string> = {
  allowed: 'Allowed',
  blocked: 'Blocked',
  sanitized: 'Sanitized',
  poisoning: 'Tool poisoning',
  approval: 'Approval',
};

/** Which group each gateway event type belongs to. Exhaustive on purpose. */
const CATEGORY_OF: Record<McpEventType, EventCategory> = {
  TOOL_CALL_ALLOWED: 'allowed',
  TOOL_NOT_ALLOWED: 'blocked',
  ARGS_DLP_BLOCKED: 'blocked',
  ARGS_DLP_REDACTED: 'blocked',
  // the proxy fails closed when the gateway is down: the call does not go through
  GATEWAY_UNAVAILABLE: 'blocked',
  RESULT_REDACTED: 'sanitized',
  RESULT_INJECTION_REMOVED: 'sanitized',
  TOOL_POISONING_SUSPECTED: 'poisoning',
  TOOL_DEFINITION_CHANGED: 'poisoning',
  APPROVAL_REQUESTED: 'approval',
  APPROVAL_GRANTED: 'approval',
  APPROVAL_DENIED: 'approval',
  APPROVAL_EXPIRED: 'approval',
};

export const EVENT_LABELS: Record<McpEventType, string> = {
  TOOL_CALL_ALLOWED: 'Tool call allowed',
  TOOL_NOT_ALLOWED: 'Tool not allowed',
  ARGS_DLP_BLOCKED: 'Arguments blocked (DLP)',
  ARGS_DLP_REDACTED: 'Arguments redacted (DLP)',
  RESULT_REDACTED: 'Result redacted',
  RESULT_INJECTION_REMOVED: 'Injection removed',
  TOOL_POISONING_SUSPECTED: 'Tool poisoning suspected',
  TOOL_DEFINITION_CHANGED: 'Tool definition changed',
  APPROVAL_REQUESTED: 'Approval requested',
  APPROVAL_GRANTED: 'Approval granted',
  APPROVAL_DENIED: 'Approval denied',
  APPROVAL_EXPIRED: 'Approval expired',
  GATEWAY_UNAVAILABLE: 'Gateway unavailable',
};

export function categoryOf(type: McpEventType): EventCategory {
  return CATEGORY_OF[type];
}

export function labelOf(type: McpEventType): string {
  return EVENT_LABELS[type];
}

// --- stat cards ----------------------------------------------------------------

function count(stats: McpStats, type: McpEventType): number {
  return stats.by_event_type[type] ?? 0;
}

export interface AgentTotals {
  allowed: number;
  /** TOOL_NOT_ALLOWED + ARGS_DLP_BLOCKED + ARGS_DLP_REDACTED */
  blocked: number;
  injectionsRemoved: number;
  resultsRedacted: number;
  /** TOOL_POISONING_SUSPECTED + TOOL_DEFINITION_CHANGED */
  poisoning: number;
  granted: number;
  denied: number;
  expired: number;
  pending: number;
}

/** The numbers on the stat cards, derived from GET /mcp/stats. */
export function agentTotals(stats: McpStats): AgentTotals {
  return {
    allowed: count(stats, 'TOOL_CALL_ALLOWED'),
    blocked:
      count(stats, 'TOOL_NOT_ALLOWED') + count(stats, 'ARGS_DLP_BLOCKED') + count(stats, 'ARGS_DLP_REDACTED'),
    injectionsRemoved: count(stats, 'RESULT_INJECTION_REMOVED'),
    resultsRedacted: count(stats, 'RESULT_REDACTED'),
    poisoning: count(stats, 'TOOL_POISONING_SUSPECTED') + count(stats, 'TOOL_DEFINITION_CHANGED'),
    granted: count(stats, 'APPROVAL_GRANTED'),
    denied: count(stats, 'APPROVAL_DENIED'),
    expired: count(stats, 'APPROVAL_EXPIRED'),
    pending: stats.pending_approvals,
  };
}

// --- filters -------------------------------------------------------------------

export interface AgentFilters {
  category: EventCategory | 'all';
  tool: string | 'all';
  search: string;
  range: TimeRange;
}

export const DEFAULT_AGENT_FILTERS: AgentFilters = {
  category: 'all',
  tool: 'all',
  search: '',
  range: '24h',
};

const HOUR_MS = 3_600_000;

/** Keep the events that match every filter. The order is preserved. */
export function filterEvents(
  events: readonly McpEvent[],
  filters: AgentFilters,
  now: number = Date.now(),
): McpEvent[] {
  const cutoff = now - RANGE_HOURS[filters.range] * HOUR_MS;
  const needle = filters.search.trim().toLowerCase();

  return events.filter((event) => {
    if (filters.category !== 'all' && categoryOf(event.event_type) !== filters.category) return false;
    if (filters.tool !== 'all' && event.tool_name !== filters.tool) return false;
    const time = Date.parse(event.timestamp);
    if (Number.isNaN(time) || time < cutoff) return false;
    if (needle) {
      const haystack = [
        labelOf(event.event_type),
        event.event_type,
        event.tool_name ?? '',
        event.server_name,
        event.decision,
        event.details,
        ...event.data_types,
      ]
        .join('\n')
        .toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    return true;
  });
}

/** The tool names that appear in the events, sorted. */
export function collectTools(events: readonly McpEvent[]): string[] {
  const tools = new Set<string>();
  for (const event of events) if (event.tool_name) tools.add(event.tool_name);
  return [...tools].sort();
}

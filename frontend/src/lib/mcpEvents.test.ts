import { describe, expect, it } from 'vitest';

import { MCP_EVENT_TYPES, type McpStats } from '../api/types';
import { makeMcpEvent, MCP_STATS, minutesAgo, sampleMcpEvents } from '../test/fixtures';
import {
  agentTotals,
  categoryOf,
  collectTools,
  DEFAULT_AGENT_FILTERS,
  EVENT_CATEGORIES,
  EVENT_LABELS,
  filterEvents,
  labelOf,
} from './mcpEvents';

describe('categoryOf', () => {
  it.each([
    ['TOOL_CALL_ALLOWED', 'allowed'],
    ['TOOL_NOT_ALLOWED', 'blocked'],
    ['ARGS_DLP_BLOCKED', 'blocked'],
    ['ARGS_DLP_REDACTED', 'blocked'],
    ['GATEWAY_UNAVAILABLE', 'blocked'],
    ['RESULT_REDACTED', 'sanitized'],
    ['RESULT_INJECTION_REMOVED', 'sanitized'],
    ['TOOL_POISONING_SUSPECTED', 'poisoning'],
    ['TOOL_DEFINITION_CHANGED', 'poisoning'],
    ['APPROVAL_REQUESTED', 'approval'],
    ['APPROVAL_GRANTED', 'approval'],
    ['APPROVAL_DENIED', 'approval'],
    ['APPROVAL_EXPIRED', 'approval'],
  ] as const)('%s -> %s', (type, category) => {
    expect(categoryOf(type)).toBe(category);
  });

  it('covers every event type the gateway knows, with a label each', () => {
    for (const type of MCP_EVENT_TYPES) {
      expect(EVENT_CATEGORIES).toContain(categoryOf(type));
      expect(labelOf(type)).toBe(EVENT_LABELS[type]);
      expect(labelOf(type)).not.toMatch(/_/);
    }
  });
});

describe('agentTotals', () => {
  it('adds up the blocked and poisoning groups', () => {
    expect(agentTotals(MCP_STATS)).toEqual({
      allowed: 15,
      blocked: 6, // 2 not allowed + 3 DLP blocked + 1 DLP redacted
      injectionsRemoved: 3,
      resultsRedacted: 4,
      poisoning: 3, // 1 suspected + 2 definition changed
      granted: 3,
      denied: 1,
      expired: 1,
      pending: 2,
    });
  });

  it('treats a missing event type as zero', () => {
    const empty: McpStats = { total_events: 0, by_event_type: {}, by_decision: {}, pending_approvals: 0 };
    expect(agentTotals(empty)).toEqual({
      allowed: 0,
      blocked: 0,
      injectionsRemoved: 0,
      resultsRedacted: 0,
      poisoning: 0,
      granted: 0,
      denied: 0,
      expired: 0,
      pending: 0,
    });
  });
});

describe('filterEvents', () => {
  const events = sampleMcpEvents();
  const now = Date.now();
  const ids = (list: ReturnType<typeof filterEvents>) => list.map((e) => e.id);

  it('keeps everything in range with the default filters', () => {
    expect(filterEvents(events, DEFAULT_AGENT_FILTERS, now)).toHaveLength(events.length);
  });

  it('filters by category', () => {
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, category: 'approval' }, now))).toEqual([8, 7]);
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, category: 'blocked' }, now))).toEqual([4, 3]);
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, category: 'sanitized' }, now))).toEqual([6, 5]);
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, category: 'poisoning' }, now))).toEqual([9]);
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, category: 'allowed' }, now))).toEqual([2, 1]);
  });

  it('filters by tool', () => {
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, tool: 'list_documents' }, now))).toEqual([2]);
    expect(ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, tool: 'nope' }, now))).toEqual([]);
  });

  it('searches label, type, tool, server, decision, details and data types, ignoring case', () => {
    const search = (text: string) => ids(filterEvents(events, { ...DEFAULT_AGENT_FILTERS, search: text }, now));
    expect(search('INJECTION REMOVED')).toEqual([5]); // label
    expect(search('args_dlp')).toEqual([4]); // event type
    expect(search('delete_every')).toEqual([3]); // tool
    expect(search('corp-docs')).toHaveLength(events.length); // server
    expect(search('quarantine')).toEqual([9]); // decision
    expect(search('allowlist')).toEqual([3]); // details
    expect(search('iban')).toEqual([6]); // data type
    expect(search('  allowlist  ')).toEqual([3]); // trimmed
    expect(search('no such text')).toEqual([]);
  });

  it('applies the time range', () => {
    const old = makeMcpEvent({ id: 100, timestamp: minutesAgo(90) });
    expect(ids(filterEvents([old], { ...DEFAULT_AGENT_FILTERS, range: '1h' }, now))).toEqual([]);
    expect(ids(filterEvents([old], { ...DEFAULT_AGENT_FILTERS, range: '24h' }, now))).toEqual([100]);
  });

  it('drops events with an unreadable time', () => {
    expect(filterEvents([makeMcpEvent({ timestamp: 'bad' })], DEFAULT_AGENT_FILTERS, now)).toEqual([]);
  });

  it('combines filters', () => {
    const result = filterEvents(
      events,
      { ...DEFAULT_AGENT_FILTERS, category: 'blocked', tool: 'send_email', search: 'credit' },
      now,
    );
    expect(ids(result)).toEqual([4]);
  });
});

describe('collectTools', () => {
  it('lists each tool once, sorted, and skips events without a tool', () => {
    const events = [
      makeMcpEvent({ tool_name: 'send_email' }),
      makeMcpEvent({ tool_name: 'read_document' }),
      makeMcpEvent({ tool_name: 'send_email' }),
      makeMcpEvent({ tool_name: null }),
    ];
    expect(collectTools(events)).toEqual(['read_document', 'send_email']);
  });
});

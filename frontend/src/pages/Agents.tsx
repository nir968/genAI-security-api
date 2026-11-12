import { Fragment, useMemo, useState, type ReactNode } from 'react';

import { MCP_EVENT_LIMIT } from '../api/client';
import { useMcpEvents, useMcpStats } from '../api/hooks';
import { EventBadge } from '../components/EventBadge';
import { DataTypeChip, EmptyState, ErrorNotice, HighlightedRich, RangeSelector, Skeleton } from '../components/ui';
import { RANGE_HOURS } from '../lib/buckets';
import { sortNewestFirst, paginate } from '../lib/filters';
import { formatTimestamp, truncate } from '../lib/format';
import {
  agentTotals,
  CATEGORY_LABELS,
  collectTools,
  DEFAULT_AGENT_FILTERS,
  EVENT_CATEGORIES,
  filterEvents,
  type AgentFilters,
  type EventCategory,
} from '../lib/mcpEvents';

export const README_URL = 'https://github.com/nir968/genAI-security-api#agent-security-mcp';

const PREVIEW_CHARS = 80;

function StatCard({ label, accent, children }: { label: string; accent: string; children: ReactNode }) {
  return (
    <div className="panel p-4" role="group" aria-label={label}>
      <p className="text-sm text-ink-dim">{label}</p>
      <div className={`mt-1 text-3xl font-semibold tabular-nums ${accent}`}>{children}</div>
    </div>
  );
}

function StatCards() {
  const stats = useMcpStats();
  const totals = stats.data ? agentTotals(stats.data) : null;
  const number = (value: number | undefined) =>
    totals ? (
      (value ?? 0).toLocaleString('en-US')
    ) : stats.isError ? (
      <span className="text-ink-mute" title="Unavailable">
        —
      </span>
    ) : (
      <Skeleton className="mt-2 h-8 w-16" />
    );

  return (
    <section aria-label="Agent security statistics" className="space-y-2">
      <p className="text-xs text-ink-mute">All time</p>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Tool calls allowed" accent="text-emerald-300">
          {number(totals?.allowed)}
        </StatCard>
        <StatCard label="Calls blocked" accent="text-red-300">
          {number(totals?.blocked)}
        </StatCard>
        <StatCard label="Injections removed" accent="text-sky-300">
          {number(totals?.injectionsRemoved)}
        </StatCard>
        <StatCard label="Results redacted" accent="text-sky-300">
          {number(totals?.resultsRedacted)}
        </StatCard>
        <StatCard label="Tool poisoning" accent="text-amber-300">
          {number(totals?.poisoning)}
        </StatCard>
        <div className="panel p-4" role="group" aria-label="Approvals">
          <p className="text-sm text-ink-dim">Approvals</p>
          {totals ? (
            <dl className="mt-1 space-y-0.5 text-sm tabular-nums">
              <div className="flex justify-between gap-2">
                <dt className="text-ink-dim">Granted</dt>
                <dd className="font-semibold text-emerald-300">{totals.granted}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-ink-dim">Denied</dt>
                <dd className="font-semibold text-red-300">{totals.denied}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-ink-dim">Expired</dt>
                <dd className="font-semibold text-amber-300">{totals.expired}</dd>
              </div>
            </dl>
          ) : stats.isError ? (
            <p className="mt-1 text-3xl font-semibold text-ink-mute" title="Unavailable">
              —
            </p>
          ) : (
            <Skeleton className="mt-2 h-8 w-16" />
          )}
        </div>
      </div>
    </section>
  );
}

const CONTROLS: { name: string; text: string }[] = [
  {
    name: 'Allowlist',
    text: 'The agent can only use the tools the policy lists. Anything else is refused before it reaches the server.',
  },
  {
    name: 'Tool pinning',
    text: 'The first version of each tool definition is remembered. If a tool later changes its description or inputs (a "rug pull"), it is blocked until a person resets the pin.',
  },
  {
    name: 'Argument DLP',
    text: 'What the agent sends to a tool is scanned for cards, IBANs, secrets and other sensitive data. Dangerous calls are blocked, and the rest is masked.',
  },
  {
    name: 'Human approval',
    text: 'Sensitive actions, such as email to an outside address, wait for a person to approve the exact call on the Approvals page.',
  },
  {
    name: 'Result scanning',
    text: 'What a tool returns is cleaned before the agent reads it: hidden instructions are removed and sensitive data is masked.',
  },
];

function HowItWorks() {
  return (
    <details className="panel group p-4">
      <summary className="text-sm font-semibold text-ink">How the proxy protects agents</summary>
      <div className="mt-3 space-y-3 text-sm text-ink-dim">
        <p>
          The agent talks to a security proxy instead of the tool server. The proxy applies five controls to
          every call and reports each decision to the gateway, which is what you see on this page.
        </p>
        <ol className="list-decimal space-y-2 pl-5">
          {CONTROLS.map((control) => (
            <li key={control.name}>
              <strong className="font-semibold text-ink">{control.name}.</strong> {control.text}
            </li>
          ))}
        </ol>
        <p>
          <a className="text-sky-300 underline" href={README_URL} target="_blank" rel="noreferrer noopener">
            Read the full explanation in the README
          </a>
        </p>
      </div>
    </details>
  );
}

function FilterBar({
  filters,
  tools,
  onChange,
}: {
  filters: AgentFilters;
  tools: string[];
  onChange: (patch: Partial<AgentFilters>) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Event type
        <select
          className="field"
          value={filters.category}
          onChange={(e) => onChange({ category: e.target.value as EventCategory | 'all' })}
        >
          <option value="all">All event types</option>
          {EVENT_CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {CATEGORY_LABELS[category]}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Tool
        <select className="field" value={filters.tool} onChange={(e) => onChange({ tool: e.target.value })}>
          <option value="all">All tools</option>
          {tools.map((tool) => (
            <option key={tool} value={tool}>
              {tool}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Search
        <input
          type="search"
          className="field"
          placeholder="Tool, details or data type"
          value={filters.search}
          onChange={(e) => onChange({ search: e.target.value })}
        />
      </label>
      <div className="flex flex-col gap-1 text-sm text-ink-dim">
        <span>Time range</span>
        <RangeSelector value={filters.range} onChange={(range) => onChange({ range })} label="Time range" />
      </div>
    </div>
  );
}

export function Agents() {
  const [filters, setFilters] = useState<AgentFilters>(DEFAULT_AGENT_FILTERS);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(new Set());

  const result = useMcpEvents(RANGE_HOURS[filters.range]);
  const events = result.data?.events;
  const now = result.dataUpdatedAt;

  const tools = useMemo(() => (events ? collectTools(events) : []), [events]);
  const rows = useMemo(
    () => (events ? sortNewestFirst(filterEvents(events, filters, now)) : []),
    [events, filters, now],
  );
  const current = paginate(rows, page);
  const truncated = events !== undefined && events.length >= MCP_EVENT_LIMIT;

  function change(patch: Partial<AgentFilters>) {
    setFilters((previous) => ({ ...previous, ...patch }));
    setPage(1);
  }

  function toggle(id: number) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Agent security</h2>
      <StatCards />
      <HowItWorks />

      <section className="panel p-4" aria-label="Filters">
        <FilterBar filters={filters} tools={tools} onChange={change} />
      </section>

      <section className="panel overflow-hidden" aria-label="Agent events">
        {result.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : result.isError ? (
          <div className="p-4">
            <ErrorNotice>Could not load agent events from the gateway.</ErrorNotice>
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No events match"
            hint="Widen the time range or clear a filter. Run the demo agent to create some."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[56rem] text-left text-sm">
                <caption className="sr-only">Agent security events, newest first</caption>
                <thead className="border-b border-line bg-panel-raised text-xs uppercase tracking-wide text-ink-mute">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">Time</th>
                    <th scope="col" className="px-3 py-2 font-medium">Event</th>
                    <th scope="col" className="px-3 py-2 font-medium">Tool</th>
                    <th scope="col" className="px-3 py-2 font-medium">Decision</th>
                    <th scope="col" className="px-3 py-2 font-medium">Data types</th>
                    <th scope="col" className="px-3 py-2 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {current.items.map((event) => {
                    const open = expanded.has(event.id);
                    const detailId = `agent-event-detail-${event.id}`;
                    return (
                      <Fragment key={event.id}>
                        <tr className="border-b border-line align-top">
                          <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                            <time dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time>
                          </td>
                          <td className="px-3 py-2">
                            <EventBadge type={event.event_type} />
                          </td>
                          <td className="px-3 py-2 font-mono">{event.tool_name ?? '—'}</td>
                          <td className="px-3 py-2 text-ink-dim">{event.decision}</td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              {event.data_types.map((dataType) => (
                                <DataTypeChip key={dataType} dataType={dataType} />
                              ))}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            {event.details ? (
                              <button
                                type="button"
                                aria-expanded={open}
                                aria-controls={detailId}
                                onClick={() => toggle(event.id)}
                                className="max-w-md text-left text-ink hover:underline"
                                title={open ? 'Hide details' : 'Show details'}
                              >
                                {truncate(event.details, PREVIEW_CHARS)}
                              </button>
                            ) : (
                              <span className="text-ink-mute">—</span>
                            )}
                          </td>
                        </tr>
                        {open ? (
                          <tr id={detailId} className="border-b border-line bg-page">
                            <td colSpan={6} className="px-3 py-3">
                              <p className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-ink">
                                <HighlightedRich text={event.details} />
                              </p>
                              <p className="mt-2 text-xs text-ink-mute">
                                Server {event.server_name} · risk score {event.risk_score}
                              </p>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <nav aria-label="Pagination" className="flex items-center justify-between gap-3 px-3 py-3 text-sm">
              <p className="text-ink-dim" aria-live="polite">
                Page {current.page} of {current.pageCount} · {current.total} events
                {truncated ? ` (newest ${MCP_EVENT_LIMIT} loaded)` : ''}
              </p>
              <div className="flex gap-2">
                <button type="button" className="btn" onClick={() => setPage(current.page - 1)} disabled={current.page <= 1}>
                  Previous
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => setPage(current.page + 1)}
                  disabled={current.page >= current.pageCount}
                >
                  Next
                </button>
              </div>
            </nav>
          </>
        )}
      </section>
    </div>
  );
}

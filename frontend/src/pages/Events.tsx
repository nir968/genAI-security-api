import { Fragment, useMemo, useState } from 'react';

import { EXPORT_EXCEL_URL } from '../api/client';
import { useHistory } from '../api/hooks';
import { ACTIONS, DIRECTIONS, type Action, type Direction, type HistoryRecord } from '../api/types';
import { ACTION_LABELS, ActionBadge } from '../components/ActionBadge';
import { DataTypeChip, EmptyState, ErrorNotice, HighlightedMasks, RangeSelector, Skeleton } from '../components/ui';
import { RANGE_HOURS } from '../lib/buckets';
import { buildCsv } from '../lib/csv';
import { collectDataTypes } from '../lib/dataTypes';
import { downloadTextFile } from '../lib/download';
import { DEFAULT_FILTERS, filterRecords, paginate, sortNewestFirst, type EventFilters } from '../lib/filters';
import { formatTimestamp, truncate } from '../lib/format';

const PREVIEW_CHARS = 80;

function rowKey(record: HistoryRecord): string {
  return `${record.timestamp}|${record.direction}|${record.prompt}`;
}

function FilterBar({
  filters,
  dataTypes,
  onChange,
}: {
  filters: EventFilters;
  dataTypes: string[];
  onChange: (patch: Partial<EventFilters>) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Action
        <select
          className="field"
          value={filters.action}
          onChange={(e) => onChange({ action: e.target.value as Action | 'all' })}
        >
          <option value="all">All actions</option>
          {ACTIONS.map((action) => (
            <option key={action} value={action}>
              {ACTION_LABELS[action]}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Direction
        <select
          className="field"
          value={filters.direction}
          onChange={(e) => onChange({ direction: e.target.value as Direction | 'all' })}
        >
          <option value="all">Both directions</option>
          {DIRECTIONS.map((direction) => (
            <option key={direction} value={direction}>
              {direction}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-dim">
        Data type
        <select className="field" value={filters.dataType} onChange={(e) => onChange({ dataType: e.target.value })}>
          <option value="all">All data types</option>
          {dataTypes.map((dataType) => (
            <option key={dataType} value={dataType}>
              {dataType}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm text-ink-dim sm:col-span-2 lg:col-span-1">
        Search
        <input
          type="search"
          className="field"
          placeholder="Prompt, threat or data type"
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

export function Events() {
  const [filters, setFilters] = useState<EventFilters>(DEFAULT_FILTERS);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  // the server only needs to return the selected window
  const history = useHistory(RANGE_HOURS[filters.range]);
  const records = history.data?.records;
  const now = history.dataUpdatedAt;

  const dataTypes = useMemo(() => (records ? collectDataTypes(records) : []), [records]);
  const rows = useMemo(
    () => (records ? sortNewestFirst(filterRecords(records, filters, now)) : []),
    [records, filters, now],
  );
  const current = paginate(rows, page);

  function change(patch: Partial<EventFilters>) {
    setFilters((previous) => ({ ...previous, ...patch }));
    setPage(1);
  }

  function toggle(key: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  }

  function exportCsv() {
    const stamp = new Date().toISOString().slice(0, 10);
    downloadTextFile(`security-events-${stamp}.csv`, buildCsv(rows), 'text/csv;charset=utf-8');
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Events</h2>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn" onClick={exportCsv} disabled={rows.length === 0}>
            Export CSV
          </button>
          <a className="btn" href={EXPORT_EXCEL_URL} download>
            Download Excel
          </a>
        </div>
      </div>

      <section className="panel p-4" aria-label="Filters">
        <FilterBar filters={filters} dataTypes={dataTypes} onChange={change} />
      </section>

      <section className="panel overflow-hidden" aria-label="Event log">
        {history.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : history.isError ? (
          <div className="p-4">
            <ErrorNotice>Could not load events from the gateway.</ErrorNotice>
          </div>
        ) : rows.length === 0 ? (
          <EmptyState title="No events match" hint="Widen the time range or clear a filter." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[56rem] text-left text-sm">
                <caption className="sr-only">Gateway events, newest first</caption>
                <thead className="border-b border-line bg-panel-raised text-xs uppercase tracking-wide text-ink-mute">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">Time</th>
                    <th scope="col" className="px-3 py-2 font-medium">Direction</th>
                    <th scope="col" className="px-3 py-2 font-medium">Action</th>
                    <th scope="col" className="px-3 py-2 font-medium">Threat</th>
                    <th scope="col" className="px-3 py-2 font-medium">Data types</th>
                    <th scope="col" className="px-3 py-2 text-right font-medium">Risk</th>
                    <th scope="col" className="px-3 py-2 font-medium">Prompt</th>
                  </tr>
                </thead>
                <tbody>
                  {current.items.map((record, index) => {
                    const key = rowKey(record);
                    const open = expanded.has(key);
                    const detailId = `event-detail-${index}`;
                    return (
                      <Fragment key={key}>
                        <tr className="border-b border-line align-top">
                          <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                            <time dateTime={record.timestamp}>{formatTimestamp(record.timestamp)}</time>
                          </td>
                          <td className="px-3 py-2 text-ink-dim">{record.direction}</td>
                          <td className="px-3 py-2">
                            <ActionBadge action={record.action} />
                          </td>
                          <td className="px-3 py-2">{record.threat_type}</td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              {record.data_types.map((dataType) => (
                                <DataTypeChip key={dataType} dataType={dataType} />
                              ))}
                            </div>
                          </td>
                          <td className="px-3 py-2 text-right tabular-nums">{record.risk_score}</td>
                          <td className="px-3 py-2">
                            <button
                              type="button"
                              aria-expanded={open}
                              aria-controls={detailId}
                              onClick={() => toggle(key)}
                              className="max-w-md text-left text-ink hover:underline"
                              title={open ? 'Hide full text' : 'Show full text'}
                            >
                              {truncate(record.prompt, PREVIEW_CHARS)}
                            </button>
                          </td>
                        </tr>
                        {open ? (
                          <tr id={detailId} className="border-b border-line bg-page">
                            <td colSpan={7} className="px-3 py-3">
                              <p className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-ink">
                                <HighlightedMasks text={record.prompt} />
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

import type { Action, Direction, HistoryRecord } from '../api/types';
import { RANGE_HOURS, type TimeRange } from './buckets';

export interface EventFilters {
  action: Action | 'all';
  direction: Direction | 'all';
  dataType: string | 'all';
  search: string;
  range: TimeRange;
}

export const DEFAULT_FILTERS: EventFilters = {
  action: 'all',
  direction: 'all',
  dataType: 'all',
  search: '',
  range: '24h',
};

const HOUR_MS = 3_600_000;

/** Keep the records that match every filter. The order is preserved. */
export function filterRecords(
  records: readonly HistoryRecord[],
  filters: EventFilters,
  now: number = Date.now(),
): HistoryRecord[] {
  const cutoff = now - RANGE_HOURS[filters.range] * HOUR_MS;
  const needle = filters.search.trim().toLowerCase();

  return records.filter((record) => {
    if (filters.action !== 'all' && record.action !== filters.action) return false;
    if (filters.direction !== 'all' && record.direction !== filters.direction) return false;
    if (filters.dataType !== 'all' && !record.data_types.includes(filters.dataType)) {
      return false;
    }
    const time = Date.parse(record.timestamp);
    if (Number.isNaN(time) || time < cutoff) return false;
    if (needle) {
      const haystack = [record.prompt, record.threat_type, ...record.data_types]
        .join('\n')
        .toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    return true;
  });
}

/** A copy sorted by time, newest first (ties keep their original order). */
export function sortNewestFirst(records: readonly HistoryRecord[]): HistoryRecord[] {
  return records
    .map((record, index) => ({ record, index, time: Date.parse(record.timestamp) }))
    .sort((a, b) => {
      const byTime = (Number.isNaN(b.time) ? 0 : b.time) - (Number.isNaN(a.time) ? 0 : a.time);
      return byTime || a.index - b.index;
    })
    .map((entry) => entry.record);
}

export const PAGE_SIZE = 25;

export interface Page<T> {
  items: T[];
  /** 1-based, clamped into 1..pageCount */
  page: number;
  /** at least 1, even when there are no items */
  pageCount: number;
  total: number;
}

export function paginate<T>(
  items: readonly T[],
  page: number,
  pageSize: number = PAGE_SIZE,
): Page<T> {
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(Math.max(1, Math.floor(page) || 1), pageCount);
  const start = (current - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    page: current,
    pageCount,
    total: items.length,
  };
}

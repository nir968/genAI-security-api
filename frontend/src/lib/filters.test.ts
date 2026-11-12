import { describe, expect, it } from 'vitest';

import type { HistoryRecord } from '../api/types';
import { makeRecord } from '../test/fixtures';
import { DEFAULT_FILTERS, filterRecords, paginate, sortNewestFirst } from './filters';

const NOW = Date.parse('2026-06-10T12:00:00Z');
const at = (minutesBefore: number) => new Date(NOW - minutesBefore * 60_000).toISOString();

const RECORDS: HistoryRecord[] = [
  makeRecord({ timestamp: at(5), prompt: 'hello there' }),
  makeRecord({
    timestamp: at(10),
    action: 'block',
    threat_type: 'DLP Violation',
    prompt: 'my card is ****1111',
    data_types: ['CREDIT_CARD'],
  }),
  makeRecord({
    timestamp: at(30),
    action: 'redact',
    direction: 'output',
    prompt: 'iban [REDACTED:IBAN]',
    data_types: ['IBAN'],
  }),
  makeRecord({ timestamp: at(60 * 30), prompt: 'a day and a half ago' }),
  makeRecord({ timestamp: at(60 * 24 * 5), prompt: 'five days ago' }),
];

const run = (patch: Partial<typeof DEFAULT_FILTERS>) =>
  filterRecords(RECORDS, { ...DEFAULT_FILTERS, ...patch }, NOW).map((r) => r.prompt);

describe('filterRecords', () => {
  it('with the default filters keeps the last 24 hours', () => {
    expect(run({})).toEqual(['hello there', 'my card is ****1111', 'iban [REDACTED:IBAN]']);
  });

  it.each([
    ['1h', 3],
    ['24h', 3],
    ['7d', 5],
  ] as const)('range %s keeps %i records', (range, count) => {
    expect(run({ range })).toHaveLength(count);
  });

  it('the range boundary is inclusive', () => {
    const edge = [makeRecord({ timestamp: at(60) })];
    expect(filterRecords(edge, { ...DEFAULT_FILTERS, range: '1h' }, NOW)).toHaveLength(1);
    const outside = [makeRecord({ timestamp: at(60.5) })];
    expect(filterRecords(outside, { ...DEFAULT_FILTERS, range: '1h' }, NOW)).toHaveLength(0);
  });

  it('filters by action', () => {
    expect(run({ action: 'block' })).toEqual(['my card is ****1111']);
    expect(run({ action: 'alert' })).toEqual([]);
  });

  it('filters by direction', () => {
    expect(run({ direction: 'output' })).toEqual(['iban [REDACTED:IBAN]']);
    expect(run({ direction: 'input' })).toHaveLength(2);
  });

  it('filters by data type', () => {
    expect(run({ dataType: 'IBAN' })).toEqual(['iban [REDACTED:IBAN]']);
    expect(run({ dataType: 'JWT' })).toEqual([]);
  });

  it('searches prompt, threat type and data types, ignoring case and padding', () => {
    expect(run({ search: '  HELLO ' })).toEqual(['hello there']);
    expect(run({ search: 'dlp violation' })).toEqual(['my card is ****1111']);
    expect(run({ search: 'credit_card' })).toEqual(['my card is ****1111']);
    expect(run({ search: 'nothing like this' })).toEqual([]);
  });

  it('combines filters with AND', () => {
    expect(run({ action: 'block', dataType: 'IBAN' })).toEqual([]);
    expect(run({ action: 'redact', direction: 'output', search: 'iban' })).toHaveLength(1);
  });

  it('drops records with an unreadable timestamp', () => {
    const odd = [makeRecord({ timestamp: 'garbage' })];
    expect(filterRecords(odd, DEFAULT_FILTERS, NOW)).toEqual([]);
  });
});

describe('sortNewestFirst', () => {
  it('sorts by time descending without changing the input', () => {
    const input = [makeRecord({ timestamp: at(30) }), makeRecord({ timestamp: at(5) }), makeRecord({ timestamp: at(10) })];
    const before = [...input];
    expect(sortNewestFirst(input).map((r) => r.timestamp)).toEqual([at(5), at(10), at(30)]);
    expect(input).toEqual(before);
  });

  it('keeps the original order of equal timestamps', () => {
    const a = makeRecord({ timestamp: at(5), prompt: 'a' });
    const b = makeRecord({ timestamp: at(5), prompt: 'b' });
    expect(sortNewestFirst([a, b]).map((r) => r.prompt)).toEqual(['a', 'b']);
  });

  it('does not fail on unreadable timestamps', () => {
    const bad = makeRecord({ timestamp: 'garbage' });
    expect(sortNewestFirst([bad, makeRecord({ timestamp: at(1) })])).toHaveLength(2);
    expect(sortNewestFirst([makeRecord({ timestamp: at(1) }), bad])).toHaveLength(2);
  });
});

describe('paginate', () => {
  const items = Array.from({ length: 60 }, (_, i) => i + 1);

  it('returns 25 per page by default', () => {
    const page = paginate(items, 1);
    expect(page.items).toHaveLength(25);
    expect(page.items[0]).toBe(1);
    expect(page).toMatchObject({ page: 1, pageCount: 3, total: 60 });
  });

  it('returns the short last page', () => {
    const page = paginate(items, 3);
    expect(page.items).toEqual(items.slice(50));
  });

  it('clamps out-of-range and invalid pages', () => {
    expect(paginate(items, 99).page).toBe(3);
    expect(paginate(items, 0).page).toBe(1);
    expect(paginate(items, -4).page).toBe(1);
    expect(paginate(items, Number.NaN).page).toBe(1);
  });

  it('has one empty page when there are no items', () => {
    expect(paginate([], 1)).toEqual({ items: [], page: 1, pageCount: 1, total: 0 });
  });

  it('honours a custom page size', () => {
    expect(paginate(items, 2, 10).items[0]).toBe(11);
  });
});

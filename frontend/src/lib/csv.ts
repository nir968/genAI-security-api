import type { HistoryRecord } from '../api/types';

export const CSV_HEADER = [
  'timestamp',
  'direction',
  'action',
  'threat_type',
  'risk_score',
  'data_types',
  'prompt',
] as const;

const BOM = '﻿';

/**
 * Text cells that start with one of these are read as formulas by Excel and
 * LibreOffice. Prompts are user input, so they are prefixed with an apostrophe
 * (the usual defence against CSV injection).
 */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/** RFC 4180 quoting: wrap in quotes when needed and double inner quotes. */
export function escapeCsvField(value: string): string {
  const safe = FORMULA_PREFIX.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/**
 * One header row plus one row per record, CRLF separated, starting with a
 * UTF-8 byte order mark so Excel opens non-ASCII text correctly.
 */
export function buildCsv(records: readonly HistoryRecord[], withBom = true): string {
  const rows = records.map((record) =>
    [
      escapeCsvField(record.timestamp),
      escapeCsvField(record.direction),
      escapeCsvField(record.action),
      escapeCsvField(record.threat_type),
      String(record.risk_score),
      escapeCsvField(record.data_types.join(';')),
      escapeCsvField(record.prompt),
    ].join(','),
  );
  const text = [CSV_HEADER.join(','), ...rows].join('\r\n') + '\r\n';
  return withBom ? BOM + text : text;
}

import type { HistoryRecord } from '../api/types';

export interface DataTypeCount {
  dataType: string;
  count: number;
}

/**
 * How many records mention each data type (a record counts once per type).
 * Sorted by count, highest first, then by name.
 */
export function countDataTypes(records: readonly HistoryRecord[]): DataTypeCount[] {
  const counts = new Map<string, number>();
  for (const record of records) {
    for (const dataType of new Set(record.data_types)) {
      counts.set(dataType, (counts.get(dataType) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([dataType, count]) => ({ dataType, count }))
    .sort((a, b) => b.count - a.count || a.dataType.localeCompare(b.dataType));
}

/** Distinct data types that occur in the records, sorted by name. */
export function collectDataTypes(records: readonly HistoryRecord[]): string[] {
  return [...new Set(records.flatMap((record) => record.data_types))].sort();
}

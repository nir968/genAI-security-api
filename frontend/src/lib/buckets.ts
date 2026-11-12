import { ACTIONS, type HistoryRecord } from '../api/types';

export type TimeRange = '1h' | '24h' | '7d';

export const TIME_RANGES: readonly TimeRange[] = ['1h', '24h', '7d'];

export const RANGE_HOURS: Record<TimeRange, number> = { '1h': 1, '24h': 24, '7d': 168 };

/**
 * Bucket width per range. 24h and 7d are bucketed by hour. A single hourly bar
 * would make the 1h view useless, so that range uses 5-minute buckets.
 * The width must divide 60.
 */
export const BUCKET_MINUTES: Record<TimeRange, number> = { '1h': 5, '24h': 60, '7d': 60 };

export interface ActivityBucket {
  /** start of the bucket, epoch milliseconds, aligned to the viewer's local clock */
  start: number;
  allow: number;
  alert: number;
  redact: number;
  block: number;
  total: number;
}

const MINUTE_MS = 60_000;

/**
 * Round `ms` down to the start of its bucket on the viewer's *local* clock, so
 * buckets line up with the hours the viewer sees even in zones with a
 * 30 or 45 minute UTC offset.
 */
export function floorToBucket(ms: number, bucketMinutes: number): number {
  const date = new Date(ms);
  date.setMinutes(Math.floor(date.getMinutes() / bucketMinutes) * bucketMinutes, 0, 0);
  return date.getTime();
}

function emptyBucket(start: number): ActivityBucket {
  return { start, allow: 0, alert: 0, redact: 0, block: 0, total: 0 };
}

/**
 * Count records per bucket and action for the window that ends with the
 * bucket containing `now`. Every bucket in the window is returned (empty ones
 * too), oldest first. Records outside the window are ignored.
 */
export function bucketActivity(
  records: readonly HistoryRecord[],
  range: TimeRange,
  now: number = Date.now(),
): ActivityBucket[] {
  const width = BUCKET_MINUTES[range];
  const step = width * MINUTE_MS;
  const count = Math.ceil((RANGE_HOURS[range] * 60) / width);
  const lastStart = floorToBucket(now, width);

  const buckets: ActivityBucket[] = [];
  const byStart = new Map<number, ActivityBucket>();
  for (let i = 0; i < count; i += 1) {
    const bucket = emptyBucket(lastStart - (count - 1 - i) * step);
    buckets.push(bucket);
    byStart.set(bucket.start, bucket);
  }

  for (const record of records) {
    const time = Date.parse(record.timestamp);
    if (Number.isNaN(time)) continue;
    const bucket = byStart.get(floorToBucket(time, width));
    if (!bucket) continue;
    // an unexpected action value from a newer gateway is skipped, not miscounted
    if (ACTIONS.includes(record.action)) {
      bucket[record.action] += 1;
      bucket.total += 1;
    }
  }
  return buckets;
}

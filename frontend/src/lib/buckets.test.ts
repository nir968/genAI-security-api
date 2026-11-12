import { afterEach, describe, expect, it } from 'vitest';

import { makeRecord } from '../test/fixtures';
import { BUCKET_MINUTES, bucketActivity, floorToBucket, RANGE_HOURS } from './buckets';

const HOUR = 3_600_000;
const originalTz = process.env.TZ;

function useTimeZone(tz: string, expectedOffsetMinutes: number) {
  process.env.TZ = tz;
  // guard against a runtime that ignores TZ changes: the test would prove nothing
  expect(new Date(Date.UTC(2026, 0, 15, 12)).getTimezoneOffset()).toBe(expectedOffsetMinutes);
}

afterEach(() => {
  if (originalTz === undefined) delete process.env.TZ;
  else process.env.TZ = originalTz;
});

describe('floorToBucket across time zones', () => {
  // [zone, January UTC offset in getTimezoneOffset() terms, instant, expected bucket start]
  it.each([
    ['UTC', 0, '2026-06-10T12:15:30Z', '2026-06-10T12:00:00Z'],
    ['America/New_York', 300, '2026-01-15T12:15:30Z', '2026-01-15T12:00:00Z'],
    // UTC+5:30: local hours start at :30 UTC
    ['Asia/Kolkata', -330, '2026-06-10T12:15:30Z', '2026-06-10T11:30:00Z'],
    // UTC+5:45
    ['Asia/Kathmandu', -345, '2026-06-10T12:20:00Z', '2026-06-10T12:15:00Z'],
    ['Asia/Tokyo', -540, '2026-06-10T23:59:59Z', '2026-06-10T23:00:00Z'],
  ])('%s: hourly buckets start on the local hour', (tz, offset, instant, expected) => {
    useTimeZone(tz, offset);
    expect(floorToBucket(Date.parse(instant), 60)).toBe(Date.parse(expected));
  });

  it('floors to 5 minute buckets', () => {
    useTimeZone('UTC', 0);
    expect(floorToBucket(Date.parse('2026-06-10T12:14:59.999Z'), 5)).toBe(Date.parse('2026-06-10T12:10:00Z'));
    expect(floorToBucket(Date.parse('2026-06-10T12:15:00Z'), 5)).toBe(Date.parse('2026-06-10T12:15:00Z'));
  });
});

describe('bucketActivity', () => {
  const NOW = Date.parse('2026-06-10T12:30:00Z');

  it('returns one empty bucket per slot, oldest first, ending with the current one', () => {
    useTimeZone('UTC', 0);
    const buckets = bucketActivity([], '24h', NOW);
    expect(buckets).toHaveLength(24);
    expect(buckets[23]?.start).toBe(Date.parse('2026-06-10T12:00:00Z'));
    expect(buckets[0]?.start).toBe(Date.parse('2026-06-09T13:00:00Z'));
    expect(buckets.every((b) => b.total === 0)).toBe(true);
  });

  it.each([
    ['1h', 12],
    ['24h', 24],
    ['7d', 168],
  ] as const)('%s has %i buckets', (range, count) => {
    useTimeZone('UTC', 0);
    const buckets = bucketActivity([], range, NOW);
    expect(buckets).toHaveLength(count);
    expect(count * BUCKET_MINUTES[range]).toBe(RANGE_HOURS[range] * 60);
  });

  it('puts events on either side of an hour boundary into different buckets', () => {
    useTimeZone('UTC', 0);
    const buckets = bucketActivity(
      [
        makeRecord({ timestamp: '2026-06-10T11:59:59.999Z' }),
        makeRecord({ timestamp: '2026-06-10T12:00:00Z', action: 'block' }),
      ],
      '24h',
      NOW,
    );
    const eleven = buckets.find((b) => b.start === Date.parse('2026-06-10T11:00:00Z'));
    const twelve = buckets.find((b) => b.start === Date.parse('2026-06-10T12:00:00Z'));
    expect(eleven).toMatchObject({ allow: 1, block: 0, total: 1 });
    expect(twelve).toMatchObject({ allow: 0, block: 1, total: 1 });
  });

  it('counts each action separately', () => {
    useTimeZone('UTC', 0);
    const at = '2026-06-10T12:05:00Z';
    const buckets = bucketActivity(
      [
        makeRecord({ timestamp: at, action: 'allow' }),
        makeRecord({ timestamp: at, action: 'allow' }),
        makeRecord({ timestamp: at, action: 'alert' }),
        makeRecord({ timestamp: at, action: 'redact' }),
        makeRecord({ timestamp: at, action: 'block' }),
      ],
      '24h',
      NOW,
    );
    expect(buckets[23]).toMatchObject({ allow: 2, alert: 1, redact: 1, block: 1, total: 5 });
  });

  it('uses the viewer’s local hours (UTC+5:30) for the bucket edges', () => {
    useTimeZone('Asia/Kolkata', -330);
    // 12:15Z is 17:45 in India: it belongs to the 17:00 local bucket = 11:30Z
    const buckets = bucketActivity([makeRecord({ timestamp: '2026-06-10T12:15:00Z' })], '24h', NOW);
    const hit = buckets.filter((b) => b.total > 0);
    expect(hit).toHaveLength(1);
    expect(hit[0]?.start).toBe(Date.parse('2026-06-10T11:30:00Z'));
    expect(new Date(hit[0]?.start ?? 0).getMinutes()).toBe(0);
  });

  it('keeps one-hour spacing across a daylight saving change', () => {
    useTimeZone('America/New_York', 300);
    // US clocks jump forward on 2026-03-08
    const buckets = bucketActivity([], '24h', Date.parse('2026-03-08T12:00:00Z'));
    expect(buckets).toHaveLength(24);
    for (let i = 1; i < buckets.length; i += 1) {
      expect((buckets[i]?.start ?? 0) - (buckets[i - 1]?.start ?? 0)).toBe(HOUR);
    }
    expect(buckets.every((b) => new Date(b.start).getMinutes() === 0)).toBe(true);
  });

  it('ignores events outside the window, in the future, or with bad data', () => {
    useTimeZone('UTC', 0);
    const buckets = bucketActivity(
      [
        makeRecord({ timestamp: '2026-06-08T00:00:00Z' }), // too old
        makeRecord({ timestamp: '2026-06-10T13:00:00Z' }), // next hour
        makeRecord({ timestamp: 'not a date' }),
        makeRecord({ timestamp: '2026-06-10T12:10:00Z', action: 'quarantine' as never }),
      ],
      '24h',
      NOW,
    );
    expect(buckets.reduce((sum, b) => sum + b.total, 0)).toBe(0);
  });

  it('buckets the 1h range by 5 minutes', () => {
    useTimeZone('UTC', 0);
    const buckets = bucketActivity(
      [makeRecord({ timestamp: '2026-06-10T12:07:00Z' }), makeRecord({ timestamp: '2026-06-10T12:29:00Z' })],
      '1h',
      NOW,
    );
    expect(buckets.find((b) => b.start === Date.parse('2026-06-10T12:05:00Z'))?.total).toBe(1);
    expect(buckets.find((b) => b.start === Date.parse('2026-06-10T12:25:00Z'))?.total).toBe(1);
  });
});

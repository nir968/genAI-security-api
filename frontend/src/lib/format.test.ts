import { afterEach, describe, expect, it } from 'vitest';

import { formatBucketLabel, formatTimestamp, humanizeDataType, truncate } from './format';

// newer ICU versions put a narrow no-break space before AM/PM
const plain = (text: string) => text.replace(/\s/g, ' ');
const originalTz = process.env.TZ;
afterEach(() => {
  if (originalTz === undefined) delete process.env.TZ;
  else process.env.TZ = originalTz;
});

describe('formatTimestamp', () => {
  it('shows the time in the viewer’s time zone', () => {
    process.env.TZ = 'Asia/Tokyo';
    expect(plain(formatTimestamp('2026-06-10T12:00:00Z', 'en-US'))).toBe('Jun 10, 2026, 9:00:00 PM');
    process.env.TZ = 'America/New_York';
    expect(plain(formatTimestamp('2026-06-10T12:00:00Z', 'en-US'))).toBe('Jun 10, 2026, 8:00:00 AM');
  });

  it('returns unreadable input unchanged', () => {
    expect(formatTimestamp('garbage')).toBe('garbage');
  });
});

describe('formatBucketLabel', () => {
  it('shows only the time, or the date as well', () => {
    process.env.TZ = 'UTC';
    const ms = Date.parse('2026-06-10T09:05:00Z');
    expect(plain(formatBucketLabel(ms, false, 'en-US'))).toBe('09:05 AM');
    expect(plain(formatBucketLabel(ms, true, 'en-US'))).toBe('Jun 10, 09:05 AM');
  });
});

describe('truncate', () => {
  it('keeps short text', () => {
    expect(truncate('short', 10)).toBe('short');
    expect(truncate('exactly10!', 10)).toBe('exactly10!');
  });

  it('cuts long text to the limit, with an ellipsis', () => {
    const cut = truncate('this is a long sentence', 10);
    expect(cut).toBe('this is a…');
    expect(cut.length).toBeLessThanOrEqual(10);
  });
});

describe('humanizeDataType', () => {
  it('turns constants into words', () => {
    expect(humanizeDataType('CREDIT_CARD')).toBe('Credit card');
    expect(humanizeDataType('IBAN')).toBe('Iban');
  });
});

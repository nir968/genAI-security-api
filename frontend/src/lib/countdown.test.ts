import { describe, expect, it } from 'vitest';

import { formatCountdown, isUrgent, secondsLeft, URGENT_SECONDS } from './countdown';

const NOW = Date.parse('2026-06-10T12:00:00Z');

describe('secondsLeft', () => {
  it('counts whole seconds until the expiry', () => {
    expect(secondsLeft('2026-06-10T12:02:05Z', NOW)).toBe(125);
  });

  it('rounds a partial second up, so zero only shows when time is really up', () => {
    expect(secondsLeft('2026-06-10T12:00:01Z', NOW - 400)).toBe(2);
    expect(secondsLeft('2026-06-10T12:00:00Z', NOW - 1)).toBe(1);
    expect(secondsLeft('2026-06-10T12:00:00Z', NOW)).toBe(0);
  });

  it('never goes negative', () => {
    expect(secondsLeft('2026-06-10T11:00:00Z', NOW)).toBe(0);
  });

  it('treats an unreadable date as expired', () => {
    expect(secondsLeft('soon', NOW)).toBe(0);
    expect(secondsLeft('', NOW)).toBe(0);
  });
});

describe('formatCountdown', () => {
  it.each([
    [125, '2:05'],
    [120, '2:00'],
    [59, '0:59'],
    [9, '0:09'],
    [1, '0:01'],
    [3600, '60:00'],
  ])('%i seconds -> %s', (seconds, text) => {
    expect(formatCountdown(seconds)).toBe(text);
  });

  it('says Expired at zero and below', () => {
    expect(formatCountdown(0)).toBe('Expired');
    expect(formatCountdown(-5)).toBe('Expired');
  });

  it('rounds a fractional value up', () => {
    expect(formatCountdown(4.2)).toBe('0:05');
  });
});

describe('isUrgent', () => {
  it('is true only below the threshold and above zero', () => {
    expect(isUrgent(URGENT_SECONDS)).toBe(false);
    expect(isUrgent(URGENT_SECONDS - 1)).toBe(true);
    expect(isUrgent(1)).toBe(true);
    expect(isUrgent(0)).toBe(false);
    expect(isUrgent(120)).toBe(false);
  });
});

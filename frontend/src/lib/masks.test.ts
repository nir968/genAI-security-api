import { describe, expect, it } from 'vitest';

import { splitMasks } from './masks';

describe('splitMasks', () => {
  it('returns nothing for empty text', () => {
    expect(splitMasks('')).toEqual([]);
  });

  it('returns one plain segment when there is no mask', () => {
    expect(splitMasks('hello world')).toEqual([{ text: 'hello world', masked: false }]);
  });

  it('marks a [REDACTED:TYPE] token', () => {
    expect(splitMasks('refund to [REDACTED:IBAN] today')).toEqual([
      { text: 'refund to ', masked: false },
      { text: '[REDACTED:IBAN]', masked: true },
      { text: ' today', masked: false },
    ]);
  });

  it('marks a masked card number', () => {
    expect(splitMasks('card ****1111.')).toEqual([
      { text: 'card ', masked: false },
      { text: '****1111', masked: true },
      { text: '.', masked: false },
    ]);
  });

  it('marks a masked email address', () => {
    expect(splitMasks('mail d***@example.com now')).toEqual([
      { text: 'mail ', masked: false },
      { text: 'd***@example.com', masked: true },
      { text: ' now', masked: false },
    ]);
  });

  it('handles masks at the start, at the end and next to each other', () => {
    expect(splitMasks('[REDACTED:JWT][REDACTED:IBAN]')).toEqual([
      { text: '[REDACTED:JWT]', masked: true },
      { text: '[REDACTED:IBAN]', masked: true },
    ]);
    expect(splitMasks('****1234 and [REDACTED:AWS_ACCESS_KEY]')).toEqual([
      { text: '****1234', masked: true },
      { text: ' and ', masked: false },
      { text: '[REDACTED:AWS_ACCESS_KEY]', masked: true },
    ]);
  });

  it('does not mark look-alikes', () => {
    for (const text of ['[REDACTED]', '[redacted:iban]', '***1234', '*****', 'a**@b.com']) {
      expect(splitMasks(text).every((s) => !s.masked)).toBe(true);
    }
  });

  it('joins back to the original text', () => {
    const text = 'a [REDACTED:IBAN] b ****1111 c d***@x.io e';
    expect(splitMasks(text).map((s) => s.text).join('')).toBe(text);
  });
});

import { describe, expect, it } from 'vitest';

import { makeRecord } from '../test/fixtures';
import { buildCsv, CSV_HEADER, escapeCsvField } from './csv';

describe('escapeCsvField', () => {
  it('leaves plain text alone', () => {
    expect(escapeCsvField('hello world')).toBe('hello world');
  });

  it('quotes fields with commas', () => {
    expect(escapeCsvField('a,b')).toBe('"a,b"');
  });

  it('doubles inner quotes', () => {
    expect(escapeCsvField('say "hi"')).toBe('"say ""hi"""');
  });

  it('quotes fields with newlines (LF and CRLF)', () => {
    expect(escapeCsvField('line1\nline2')).toBe('"line1\nline2"');
    expect(escapeCsvField('line1\r\nline2')).toBe('"line1\r\nline2"');
  });

  it('handles quotes, commas and newlines together', () => {
    expect(escapeCsvField('a "b", c\nd')).toBe('"a ""b"", c\nd"');
  });

  it('keeps non-ASCII text', () => {
    expect(escapeCsvField('שלום')).toBe('שלום');
  });

  it.each(['=1+1', '+1', '-1', '@SUM(A1)', '\tx'])('neutralises the formula start %j', (value) => {
    expect(escapeCsvField(value).replace(/^"/, '').startsWith("'")).toBe(true);
  });
});

describe('buildCsv', () => {
  it('starts with a UTF-8 byte order mark', () => {
    expect(buildCsv([]).charCodeAt(0)).toBe(0xfeff);
  });

  it('can leave the byte order mark out', () => {
    expect(buildCsv([], false).startsWith(CSV_HEADER.join(','))).toBe(true);
  });

  it('writes just the header for no records', () => {
    expect(buildCsv([], false)).toBe('timestamp,direction,action,threat_type,risk_score,data_types,prompt\r\n');
  });

  it('writes one escaped row per record, CRLF separated', () => {
    const csv = buildCsv(
      [
        makeRecord({
          timestamp: '2026-06-10T12:00:00Z',
          action: 'redact',
          threat_type: 'DLP Redaction',
          risk_score: 60,
          data_types: ['IBAN', 'EMAIL'],
          prompt: 'refund to [REDACTED:IBAN], "urgent"\nthanks',
        }),
        makeRecord({ prompt: 'plain' }),
      ],
      false,
    );
    expect(csv.split('\r\n')).toEqual([
      'timestamp,direction,action,threat_type,risk_score,data_types,prompt',
      '2026-06-10T12:00:00Z,input,redact,DLP Redaction,60,IBAN;EMAIL,"refund to [REDACTED:IBAN], ""urgent""\nthanks"',
      '2026-06-10T12:00:00Z,input,allow,Safe,10,,plain',
      '',
    ]);
  });
});

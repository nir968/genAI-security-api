import { describe, expect, it } from 'vitest';

import { makeApproval } from '../test/fixtures';
import { prettyArgs, recentDecisions, settledAt } from './approvals';

describe('prettyArgs', () => {
  it('indents a JSON object', () => {
    expect(prettyArgs('{"to":"b***@example.org","n":2}')).toEqual({
      text: '{\n  "to": "b***@example.org",\n  "n": 2\n}',
      json: true,
    });
  });

  it('indents a JSON array', () => {
    expect(prettyArgs('["a","b"]')).toEqual({ text: '[\n  "a",\n  "b"\n]', json: true });
  });

  it('keeps invisible-character markers and masks inside strings untouched', () => {
    const result = prettyArgs('{"subject":"Hi<U+200B>","to":"d***@corp.example"}');
    expect(result.json).toBe(true);
    expect(result.text).toContain('"Hi<U+200B>"');
    expect(result.text).toContain('d***@corp.example');
  });

  it.each([
    ['not json at all', 'not json at all'],
    ['{"to": "b***@exa', '{"to": "b***@exa'], // cut off by the gateway's length limit
    ['', ''],
    ['42', '42'],
    ['"text"', '"text"'],
    ['null', 'null'],
  ])('falls back to the raw text for %j', (raw, expected) => {
    expect(prettyArgs(raw)).toEqual({ text: expected, json: false });
  });

  it('keeps the raw text when a long number would be rounded by JSON.parse', () => {
    const raw = '{"amount": 12345678901234567890}';
    expect(prettyArgs(raw)).toEqual({ text: raw, json: false });
  });
});

describe('settledAt', () => {
  it('is the decision time, or the expiry for an approval nobody decided', () => {
    expect(settledAt(makeApproval({ decided_at: '2026-06-10T12:01:00Z' }))).toBe('2026-06-10T12:01:00Z');
    expect(settledAt(makeApproval({ decided_at: null, expires_at: '2026-06-10T12:05:00Z' }))).toBe(
      '2026-06-10T12:05:00Z',
    );
  });
});

describe('recentDecisions', () => {
  const approved = makeApproval({ id: 'a', status: 'approved', decided_at: '2026-06-10T12:03:00Z' });
  const denied = makeApproval({ id: 'b', status: 'denied', decided_at: '2026-06-10T12:05:00Z' });
  const expired = makeApproval({
    id: 'c',
    status: 'expired',
    decided_at: null,
    expires_at: '2026-06-10T12:04:00Z',
  });
  const pending = makeApproval({ id: 'd', status: 'pending' });

  it('drops pending approvals and sorts the rest newest first', () => {
    expect(recentDecisions([approved, pending, expired, denied], 10).map((a) => a.id)).toEqual([
      'b',
      'c',
      'a',
    ]);
  });

  it('keeps at most `limit`', () => {
    expect(recentDecisions([approved, denied, expired], 2).map((a) => a.id)).toEqual(['b', 'c']);
  });

  it('keeps the original order for equal or unreadable times', () => {
    const one = makeApproval({ id: 'x', status: 'denied', decided_at: 'bad' });
    const two = makeApproval({ id: 'y', status: 'denied', decided_at: 'bad' });
    expect(recentDecisions([one, two], 10).map((a) => a.id)).toEqual(['x', 'y']);
  });

  it('does not change the input', () => {
    const input = [approved, denied];
    recentDecisions(input, 10);
    expect(input.map((a) => a.id)).toEqual(['a', 'b']);
  });
});

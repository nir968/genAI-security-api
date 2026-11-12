import { afterEach, describe, expect, it, vi } from 'vitest';

import { downloadTextFile } from './download';

afterEach(() => vi.restoreAllMocks());

describe('downloadTextFile', () => {
  it('clicks a temporary link to a blob and cleans up', () => {
    const create = vi.fn((blob: Blob) => (blob ? 'blob:test-url' : ''));
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const clicked: HTMLAnchorElement[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
    });

    downloadTextFile('events.csv', 'a,b', 'text/csv');

    const blob = create.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    expect(blob?.type).toBe('text/csv');
    expect(clicked).toHaveLength(1);
    expect(clicked[0]?.download).toBe('events.csv');
    expect(clicked[0]?.href).toBe('blob:test-url');
    expect(revoke).toHaveBeenCalledWith('blob:test-url');
    expect(document.querySelector('a[download]')).toBeNull();
  });
});

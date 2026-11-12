import { describe, expect, it } from 'vitest';

import { splitInvisible, splitRich } from './invisible';

// built at run time: invisible characters in source files are easy to miss
const ZWSP = String.fromCharCode(0x200b);
const BOM = String.fromCharCode(0xfeff);
const TAG_A = String.fromCodePoint(0xe0041);

describe('splitInvisible', () => {
  it('returns nothing for empty text', () => {
    expect(splitInvisible('')).toEqual([]);
  });

  it('returns one plain segment when nothing is hidden', () => {
    expect(splitInvisible('plain text')).toEqual([{ text: 'plain text', hidden: false }]);
  });

  it('marks a <U+XXXX> token', () => {
    expect(splitInvisible('Hi<U+200B>there')).toEqual([
      { text: 'Hi', hidden: false },
      { text: '<U+200B>', hidden: true },
      { text: 'there', hidden: false },
    ]);
  });

  it('handles a marker at the start, at the end and several in a row', () => {
    expect(splitInvisible('<U+200B><U+200C>x<U+E0041>')).toEqual([
      { text: '<U+200B>', hidden: true },
      { text: '<U+200C>', hidden: true },
      { text: 'x', hidden: false },
      { text: '<U+E0041>', hidden: true },
    ]);
  });

  it('upper-cases the code of a marker', () => {
    expect(splitInvisible('<U+e0041>')).toEqual([{ text: '<U+E0041>', hidden: true }]);
  });

  it('does not treat other angle-bracket text as a marker', () => {
    expect(splitInvisible('<U+12> <b> <U+ZZZZ>')).toEqual([{ text: '<U+12> <b> <U+ZZZZ>', hidden: false }]);
  });

  it('shows a raw invisible character as the same marker', () => {
    expect(splitInvisible(`a${ZWSP}b${BOM}c${TAG_A}`)).toEqual([
      { text: 'a', hidden: false },
      { text: '<U+200B>', hidden: true },
      { text: 'b', hidden: false },
      { text: '<U+FEFF>', hidden: true },
      { text: 'c', hidden: false },
      { text: '<U+E0041>', hidden: true },
    ]);
  });

  it('can be used more than once (the pattern is global)', () => {
    expect(splitInvisible('<U+200B>')).toHaveLength(1);
    expect(splitInvisible('<U+200B>')).toHaveLength(1);
  });
});

describe('splitRich', () => {
  it('splits plain, masked and hidden parts in order', () => {
    expect(splitRich('to d***@corp.example<U+200B> card ****1111')).toEqual([
      { text: 'to ', kind: 'plain' },
      { text: 'd***@corp.example', kind: 'masked' },
      { text: '<U+200B>', kind: 'hidden' },
      { text: ' card ', kind: 'plain' },
      { text: '****1111', kind: 'masked' },
    ]);
  });

  it('returns nothing for empty text', () => {
    expect(splitRich('')).toEqual([]);
  });
});

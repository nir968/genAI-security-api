import { splitMasks } from './masks';

export interface HiddenSegment {
  text: string;
  /** true for a marker such as <U+200B>: a character a screen would not show */
  hidden: boolean;
}

/**
 * The gateway writes invisible characters in approval arguments as <U+XXXX>
 * (gateway/mcp_security.py reveal_hidden). The raw characters are matched too,
 * in case one ever arrives unconverted, and are shown as the same marker.
 */
const HIDDEN_PATTERN = new RegExp(
  [
    String.raw`<U\+[0-9A-Fa-f]{4,6}>`,
    // zero-width and soft hyphen, direction marks, bidi controls, BOM, tag characters
    String.raw`[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]`,
    String.raw`[\u{E0000}-\u{E007F}]`,
  ].join('|'),
  'gu',
);

function markerFor(char: string): string {
  if (char.startsWith('<U+')) return `<U+${char.slice(3, -1).toUpperCase()}>`;
  const code = char.codePointAt(0) ?? 0;
  return `<U+${code.toString(16).toUpperCase().padStart(4, '0')}>`;
}

/** Split text into plain segments and markers for invisible characters. */
export function splitInvisible(text: string): HiddenSegment[] {
  const segments: HiddenSegment[] = [];
  let last = 0;
  for (const match of text.matchAll(HIDDEN_PATTERN)) {
    if (match.index > last) segments.push({ text: text.slice(last, match.index), hidden: false });
    segments.push({ text: markerFor(match[0]), hidden: true });
    last = match.index + match[0].length;
  }
  if (last < text.length) segments.push({ text: text.slice(last), hidden: false });
  return segments;
}

export type RichSegment = { text: string; kind: 'plain' | 'masked' | 'hidden' };

/** Invisible markers first, then the gateway's data masks inside the plain parts. */
export function splitRich(text: string): RichSegment[] {
  return splitInvisible(text).flatMap((segment): RichSegment[] =>
    segment.hidden
      ? [{ text: segment.text, kind: 'hidden' }]
      : splitMasks(segment.text).map((part) => ({
          text: part.text,
          kind: part.masked ? 'masked' : 'plain',
        })),
  );
}

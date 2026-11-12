export interface Segment {
  text: string;
  masked: boolean;
}

/**
 * The three mask shapes the gateway writes (gateway/dlp/detectors.py):
 *   [REDACTED:IBAN]      generic
 *   ****1111             credit card, last four digits
 *   d***@example.com     email, first letter of the local part
 */
const MASK_PATTERN = new RegExp(
  [
    String.raw`\[REDACTED:[A-Z0-9_]+\]`,
    String.raw`\*{4}\d{4}`,
    String.raw`[A-Za-z0-9]\*{3}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`,
  ].join('|'),
  'g',
);

/** Split text into alternating plain and masked segments (empty ones are dropped). */
export function splitMasks(text: string): Segment[] {
  const segments: Segment[] = [];
  let last = 0;
  for (const match of text.matchAll(MASK_PATTERN)) {
    if (match.index > last) segments.push({ text: text.slice(last, match.index), masked: false });
    segments.push({ text: match[0], masked: true });
    last = match.index + match[0].length;
  }
  if (last < text.length) segments.push({ text: text.slice(last), masked: false });
  return segments;
}

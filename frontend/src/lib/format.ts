/** "Nov 12, 2026, 10:42:07 AM" in the viewer's time zone and locale. */
export function formatTimestamp(iso: string, locale?: string): string {
  const time = new Date(iso);
  if (Number.isNaN(time.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(time);
}

/** Axis label for a chart bucket: the time for short ranges, date + time for 7d. */
export function formatBucketLabel(ms: number, withDate: boolean, locale?: string): string {
  const options: Intl.DateTimeFormatOptions = withDate
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { hour: '2-digit', minute: '2-digit' };
  return new Intl.DateTimeFormat(locale, options).format(new Date(ms));
}

/** Cut text to `max` characters, ending with an ellipsis when it was shortened. */
export function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** "CREDIT_CARD" -> "Credit card" */
export function humanizeDataType(dataType: string): string {
  const words = dataType.toLowerCase().replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

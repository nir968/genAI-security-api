import type { ReactNode } from 'react';

import { splitMasks } from '../lib/masks';
import { humanizeDataType } from '../lib/format';
import { TIME_RANGES, type TimeRange } from '../lib/buckets';

export function Skeleton({ className = '' }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded bg-panel-raised ${className}`} />;
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-4 py-10 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint ? <p className="text-sm text-ink-mute">{hint}</p> : null}
    </div>
  );
}

export function ErrorNotice({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="rounded-md border border-block/50 bg-block/10 px-3 py-2 text-sm text-red-200">
      {children}
    </p>
  );
}

export function DataTypeChip({ dataType }: { dataType: string }) {
  return (
    <span
      title={humanizeDataType(dataType)}
      className="inline-block rounded border border-line bg-panel-raised px-1.5 py-0.5 font-mono text-[11px] text-ink-dim"
    >
      {dataType}
    </span>
  );
}

/** Text with every gateway mask ([REDACTED:..], ****1234, d***@host) highlighted. */
export function HighlightedMasks({ text }: { text: string }) {
  return (
    <>
      {splitMasks(text).map((segment, index) =>
        segment.masked ? (
          <mark
            key={index}
            className="rounded bg-redact/25 px-1 font-mono text-[0.92em] text-sky-200 ring-1 ring-inset ring-redact/50"
          >
            {segment.text}
          </mark>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </>
  );
}

const RANGE_LABELS: Record<TimeRange, string> = { '1h': '1 hour', '24h': '24 hours', '7d': '7 days' };

/** 1h / 24h / 7d segmented control. */
export function RangeSelector({
  value,
  onChange,
  label = 'Time range',
}: {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
  label?: string;
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-md border border-line bg-page p-0.5">
      {TIME_RANGES.map((range) => (
        <button
          key={range}
          type="button"
          aria-pressed={value === range}
          aria-label={RANGE_LABELS[range]}
          onClick={() => onChange(range)}
          className={`rounded px-3 py-1 text-sm font-medium ${
            value === range ? 'bg-redact/25 text-ink' : 'text-ink-dim hover:text-ink'
          }`}
        >
          {range}
        </button>
      ))}
    </div>
  );
}

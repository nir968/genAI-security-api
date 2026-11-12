import { useMemo, useState } from 'react';

import { useHistory, useStats } from '../api/hooks';
import type { StatsResponse } from '../api/types';
import { ActivityChart, DataTypeChart } from '../components/Charts';
import { EmptyState, ErrorNotice, RangeSelector, Skeleton } from '../components/ui';
import { bucketActivity, RANGE_HOURS, type TimeRange } from '../lib/buckets';
import { countDataTypes } from '../lib/dataTypes';

const CARDS: { key: keyof Omit<StatsResponse, 'status'>; label: string; accent: string }[] = [
  { key: 'total_requests', label: 'Total requests', accent: 'text-ink' },
  { key: 'blocked_injections', label: 'Injections blocked', accent: 'text-red-300' },
  { key: 'data_leaks_prevented', label: 'Data leaks prevented', accent: 'text-red-300' },
  { key: 'redactions', label: 'Redactions', accent: 'text-sky-300' },
  { key: 'alerts', label: 'Alerts', accent: 'text-amber-300' },
];

function StatCards() {
  const stats = useStats();
  return (
    <section aria-label="Statistics" className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
      {CARDS.map((card) => (
        <div key={card.key} className="panel p-4" role="group" aria-label={card.label}>
          <p className="text-sm text-ink-dim">{card.label}</p>
          {stats.data ? (
            <p className={`mt-1 text-3xl font-semibold tabular-nums ${card.accent}`}>
              {stats.data[card.key].toLocaleString('en-US')}
            </p>
          ) : stats.isError ? (
            <p className="mt-1 text-3xl font-semibold text-ink-mute" title="Unavailable">
              —
            </p>
          ) : (
            <Skeleton className="mt-2 h-8 w-16" />
          )}
        </div>
      ))}
    </section>
  );
}

export function Overview() {
  const [range, setRange] = useState<TimeRange>('24h');
  const history = useHistory(RANGE_HOURS[range]);

  const records = history.data?.records;
  const now = history.dataUpdatedAt;
  const buckets = useMemo(
    () => (records ? bucketActivity(records, range, now) : []),
    [records, range, now],
  );
  const counts = useMemo(() => (records ? countDataTypes(records) : []), [records]);
  const empty = records !== undefined && records.length === 0;

  return (
    <div className="space-y-6">
      <h2 className="sr-only">Overview</h2>
      <StatCards />

      <section className="panel p-4" aria-labelledby="activity-title">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h3 id="activity-title" className="text-sm font-semibold text-ink">
            Activity
          </h3>
          <RangeSelector value={range} onChange={setRange} />
        </div>
        {history.isPending ? (
          <Skeleton className="h-64 w-full" />
        ) : history.isError ? (
          <ErrorNotice>Could not load activity from the gateway.</ErrorNotice>
        ) : empty ? (
          <EmptyState title="No events in this window" hint="Send a request through the gateway to see it here." />
        ) : (
          <ActivityChart buckets={buckets} range={range} />
        )}
      </section>

      <section className="panel p-4" aria-labelledby="types-title">
        <h3 id="types-title" className="mb-3 text-sm font-semibold text-ink">
          Sensitive data by type
        </h3>
        {history.isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : history.isError ? (
          <ErrorNotice>Could not load data types from the gateway.</ErrorNotice>
        ) : counts.length === 0 ? (
          <EmptyState title="No sensitive data in this window" />
        ) : (
          <DataTypeChart counts={counts} />
        )}
      </section>
    </div>
  );
}

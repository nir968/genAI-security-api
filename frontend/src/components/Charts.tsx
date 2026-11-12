import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

import { ACTIONS, type Action } from '../api/types';
import type { DataTypeCount } from '../lib/dataTypes';
import { formatBucketLabel } from '../lib/format';
import type { ActivityBucket, TimeRange } from '../lib/buckets';
import { ACTION_LABELS } from './ActionBadge';

const TICK = { fill: '#a3adc2', fontSize: 12 };
const GRID = '#263148';
const TOOLTIP_STYLE = {
  background: '#1a2236',
  border: '1px solid #263148',
  borderRadius: 6,
  color: '#e5e9f2',
};

const ACTION_COLORS: Record<Action, string> = {
  allow: 'var(--color-allow)',
  alert: 'var(--color-alert)',
  redact: 'var(--color-redact)',
  block: 'var(--color-block)',
};

function ChartLegend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-ink-dim" aria-label="Legend">
      {ACTIONS.map((action) => (
        <li key={action} className="flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-sm" style={{ background: ACTION_COLORS[action] }} />
          {ACTION_LABELS[action]}
        </li>
      ))}
    </ul>
  );
}

/** Stacked columns: events per time bucket, split by policy action. */
export function ActivityChart({ buckets, range }: { buckets: ActivityBucket[]; range: TimeRange }) {
  const withDate = range === '7d';
  const data = buckets.map((bucket) => ({
    ...bucket,
    label: formatBucketLabel(bucket.start, withDate),
  }));
  return (
    <div>
      <ChartLegend />
      <div className="mt-3 h-64" role="img" aria-label={`Events per time bucket by action, last ${range}`}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="label" tick={TICK} stroke={GRID} interval="preserveStartEnd" minTickGap={24} />
            <YAxis tick={TICK} stroke={GRID} allowDecimals={false} />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#e5e9f2' }}
              itemStyle={{ color: '#e5e9f2' }}
              cursor={{ fill: 'rgba(163,173,194,0.12)' }}
            />
            {ACTIONS.map((action) => (
              <Bar
                key={action}
                dataKey={action}
                name={ACTION_LABELS[action]}
                stackId="actions"
                fill={ACTION_COLORS[action]}
                stroke="#111827"
                strokeWidth={1}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <details className="mt-3 text-sm">
        <summary className="text-ink-dim">View as table</summary>
        <div className="mt-2 max-h-64 overflow-auto">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Events per time bucket by action</caption>
            <thead className="text-ink-mute">
              <tr>
                <th scope="col" className="py-1 pr-3 font-medium">Time</th>
                {ACTIONS.map((action) => (
                  <th key={action} scope="col" className="py-1 pr-3 font-medium">
                    {ACTION_LABELS[action]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data
                .filter((row) => row.total > 0)
                .map((row) => (
                  <tr key={row.start} className="border-t border-line">
                    <th scope="row" className="py-1 pr-3 font-normal text-ink-dim">
                      {row.label}
                    </th>
                    {ACTIONS.map((action) => (
                      <td key={action} className="py-1 pr-3">
                        {row[action]}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

/** Horizontal bars: how many events mention each data type. One series, one colour. */
export function DataTypeChart({ counts }: { counts: DataTypeCount[] }) {
  const height = Math.max(120, counts.length * 32 + 24);
  return (
    <div>
      <div style={{ height }} role="img" aria-label="Events per sensitive data type">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={counts} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }}>
            <CartesianGrid stroke={GRID} horizontal={false} />
            <XAxis type="number" tick={TICK} stroke={GRID} allowDecimals={false} />
            <YAxis type="category" dataKey="dataType" tick={TICK} stroke={GRID} width={160} />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#e5e9f2' }}
              itemStyle={{ color: '#e5e9f2' }}
              cursor={{ fill: 'rgba(163,173,194,0.12)' }}
            />
            <Bar
              dataKey="count"
              name="Events"
              fill="var(--color-redact)"
              radius={[0, 4, 4, 0]}
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <details className="mt-3 text-sm">
        <summary className="text-ink-dim">View as table</summary>
        <table className="mt-2 w-full text-left text-sm">
          <caption className="sr-only">Events per sensitive data type</caption>
          <thead className="text-ink-mute">
            <tr>
              <th scope="col" className="py-1 pr-3 font-medium">Data type</th>
              <th scope="col" className="py-1 pr-3 font-medium">Events</th>
            </tr>
          </thead>
          <tbody>
            {counts.map((row) => (
              <tr key={row.dataType} className="border-t border-line">
                <th scope="row" className="py-1 pr-3 font-mono text-xs font-normal text-ink-dim">
                  {row.dataType}
                </th>
                <td className="py-1 pr-3">{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}

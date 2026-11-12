import { useState } from 'react';

import { usePendingApprovals, useRecentApprovals } from '../api/hooks';
import { ApprovalCard, CONFLICT_MESSAGE } from '../components/ApprovalCard';
import { StatusBadge } from '../components/EventBadge';
import { EmptyState, ErrorNotice, Skeleton } from '../components/ui';
import { settledAt } from '../lib/approvals';
import { formatTimestamp } from '../lib/format';

function PendingSection() {
  const pending = usePendingApprovals();
  // a 409 removes the card that caused it, so the message lives here
  const [conflict, setConflict] = useState(false);
  const approvals = pending.data?.approvals ?? [];

  return (
    <section aria-labelledby="pending-title" className="space-y-3">
      <h3 id="pending-title" className="text-sm font-semibold text-ink">
        Pending{' '}
        {approvals.length > 0 ? <span className="text-ink-dim">({approvals.length})</span> : null}
      </h3>

      {conflict ? (
        <div
          role="alert"
          className="flex items-start justify-between gap-3 rounded-md border border-alert/50 bg-alert/10 px-3 py-2 text-sm text-amber-100"
        >
          <p>{CONFLICT_MESSAGE}</p>
          <button type="button" className="underline" onClick={() => setConflict(false)}>
            Dismiss
          </button>
        </div>
      ) : null}

      {pending.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : pending.isError ? (
        <ErrorNotice>Could not load pending approvals from the gateway.</ErrorNotice>
      ) : approvals.length === 0 ? (
        <div className="panel">
          <EmptyState
            title="No pending approvals."
            hint="When an agent tries a sensitive action, it will appear here."
          />
        </div>
      ) : (
        <div className="space-y-4">
          {approvals.map((approval) => (
            <ApprovalCard key={approval.id} approval={approval} onConflict={() => setConflict(true)} />
          ))}
        </div>
      )}
    </section>
  );
}

function RecentSection() {
  const recent = useRecentApprovals();
  return (
    <section aria-labelledby="recent-title" className="space-y-3">
      <h3 id="recent-title" className="text-sm font-semibold text-ink">
        Recent decisions
      </h3>
      <div className="panel overflow-hidden">
        {recent.isPending ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : recent.isError ? (
          <div className="p-4">
            <ErrorNotice>Could not load recent decisions from the gateway.</ErrorNotice>
          </div>
        ) : recent.data.length === 0 ? (
          <EmptyState title="No decisions yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[32rem] text-left text-sm">
              <caption className="sr-only">Recent approval decisions, newest first</caption>
              <thead className="border-b border-line bg-panel-raised text-xs uppercase tracking-wide text-ink-mute">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Decided</th>
                  <th scope="col" className="px-3 py-2 font-medium">Status</th>
                  <th scope="col" className="px-3 py-2 font-medium">Tool</th>
                  <th scope="col" className="px-3 py-2 font-medium">Reason</th>
                </tr>
              </thead>
              <tbody>
                {recent.data.map((approval) => (
                  <tr key={approval.id} className="border-b border-line align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                      <time dateTime={settledAt(approval)}>{formatTimestamp(settledAt(approval))}</time>
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge status={approval.status} />
                    </td>
                    <td className="px-3 py-2 font-mono">
                      {approval.tool_name}
                      <span className="block text-xs text-ink-mute">{approval.server_name}</span>
                    </td>
                    <td className="px-3 py-2 text-ink-dim">{approval.reason || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

export function Approvals() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Approvals</h2>
        <p className="text-sm text-ink-dim">
          Sensitive tool calls wait here until a person approves or denies them. The list refreshes every
          3 seconds. There is no sign-in yet: anyone who can open this page can approve.
        </p>
      </div>
      <PendingSection />
      <RecentSection />
    </div>
  );
}

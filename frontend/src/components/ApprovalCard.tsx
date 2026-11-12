import { useState, type ReactNode } from 'react';

import { useDecideApproval } from '../api/hooks';
import type { ApprovalDecision, McpApproval } from '../api/types';
import { prettyArgs } from '../lib/approvals';
import { formatCountdown, isUrgent, secondsLeft } from '../lib/countdown';
import { formatTimestamp } from '../lib/format';
import { useNow } from '../lib/useNow';
import { ErrorNotice, HighlightedRich } from './ui';

export const CONFLICT_MESSAGE = 'This request was already decided or has expired';

/** Live time left. Turns red under 30 seconds and says "Expired" at zero. */
export function Countdown({ expiresAt }: { expiresAt: string }) {
  const now = useNow(1000);
  const seconds = secondsLeft(expiresAt, now);
  const expired = seconds <= 0;
  const urgent = isUrgent(seconds);
  return (
    <span
      data-urgent={urgent}
      className={`font-mono text-sm font-semibold tabular-nums ${
        expired || urgent ? 'text-red-300' : 'text-ink'
      }`}
    >
      <span className="sr-only">{expired ? 'Status: ' : 'Time left: '}</span>
      {formatCountdown(seconds)}
    </span>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-ink-mute">{label}</dt>
      <dd className="mt-0.5 text-sm text-ink">{children}</dd>
    </div>
  );
}

interface Props {
  approval: McpApproval;
  /** The gateway answered 409: someone else decided first, or it expired. */
  onConflict: () => void;
}

export function ApprovalCard({ approval, onConflict }: Props) {
  const decide = useDecideApproval(onConflict);
  const now = useNow(1000);
  const [confirming, setConfirming] = useState(false);

  const expired = secondsLeft(approval.expires_at, now) <= 0;
  const busy = decide.isPending;
  const disabled = busy || expired;
  const args = prettyArgs(approval.args_masked);
  const titleId = `approval-${approval.id}`;

  function send(decision: ApprovalDecision) {
    setConfirming(false);
    decide.mutate({ id: approval.id, decision });
  }

  return (
    <article className="panel space-y-4 p-4" aria-labelledby={titleId}>
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id={titleId} className="font-mono text-base font-semibold text-ink">
            {approval.tool_name}
          </h3>
          <p className="text-sm text-ink-dim">
            on server <span className="font-mono text-ink">{approval.server_name}</span>
          </p>
        </div>
        <p className="text-right">
          <span className="block text-xs uppercase tracking-wide text-ink-mute">Expires in</span>
          <Countdown expiresAt={approval.expires_at} />
        </p>
      </header>

      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label="Reason">{approval.reason || 'No reason given'}</Field>
        <Field label="Requested">
          <time dateTime={approval.created_at}>{formatTimestamp(approval.created_at)}</time>
        </Field>
      </dl>

      <div>
        <p className="mb-1 text-xs uppercase tracking-wide text-ink-mute">
          Arguments (sensitive values are masked{args.json ? '' : ', shown as sent'})
        </p>
        <pre
          tabIndex={0}
          aria-label="Arguments"
          className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-page p-3 font-mono text-xs leading-relaxed text-ink"
        >
          <HighlightedRich text={args.text} />
        </pre>
      </div>

      {decide.isError ? <ErrorNotice>Could not send the decision. Try again.</ErrorNotice> : null}

      <div className="flex flex-wrap items-center gap-2">
        {confirming ? (
          <>
            <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => send('approve')}>
              Confirm send
            </button>
            <button type="button" className="btn" disabled={busy} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" className="btn btn-primary" disabled={disabled} onClick={() => setConfirming(true)}>
            Approve
          </button>
        )}
        <button type="button" className="btn" disabled={disabled} onClick={() => send('deny')}>
          Deny
        </button>
        {busy ? (
          <span role="status" className="text-sm text-ink-dim">
            Sending decision…
          </span>
        ) : null}
        {expired && !busy ? <span className="text-sm text-red-300">Expired: waiting for the list to refresh</span> : null}
      </div>
    </article>
  );
}

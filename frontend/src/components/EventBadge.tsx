import type { ApprovalStatus, McpEventType } from '../api/types';
import { categoryOf, labelOf, type EventCategory } from '../lib/mcpEvents';

const BASE = 'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset';

/** One colour per category. Violet is new; the others are the gateway's action colours. */
const CATEGORY_STYLES: Record<EventCategory, { icon: string; classes: string }> = {
  allowed: { icon: '✓', classes: 'bg-allow/15 text-emerald-300 ring-allow/50' },
  blocked: { icon: '✕', classes: 'bg-block/15 text-red-300 ring-block/50' },
  sanitized: { icon: '▒', classes: 'bg-redact/15 text-sky-300 ring-redact/50' },
  poisoning: { icon: '!', classes: 'bg-alert/15 text-amber-300 ring-alert/50' },
  approval: { icon: '☑', classes: 'bg-violet-400/15 text-violet-300 ring-violet-400/50' },
};

/** The event type as a readable label, coloured by its category (never colour alone). */
export function EventBadge({ type }: { type: McpEventType }) {
  const style = CATEGORY_STYLES[categoryOf(type)];
  return (
    <span className={`${BASE} ${style.classes}`}>
      <span aria-hidden="true">{style.icon}</span>
      {labelOf(type)}
    </span>
  );
}

const STATUS_STYLES: Record<ApprovalStatus, { label: string; icon: string; classes: string }> = {
  pending: { label: 'Pending', icon: '…', classes: 'bg-violet-400/15 text-violet-300 ring-violet-400/50' },
  approved: { label: 'Approved', icon: '✓', classes: 'bg-allow/15 text-emerald-300 ring-allow/50' },
  denied: { label: 'Denied', icon: '✕', classes: 'bg-block/15 text-red-300 ring-block/50' },
  expired: { label: 'Expired', icon: '⌛', classes: 'bg-alert/15 text-amber-300 ring-alert/50' },
};

export function StatusBadge({ status }: { status: ApprovalStatus }) {
  const style = STATUS_STYLES[status];
  return (
    <span className={`${BASE} ${style.classes}`}>
      <span aria-hidden="true">{style.icon}</span>
      {style.label}
    </span>
  );
}

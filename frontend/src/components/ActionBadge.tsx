import type { Action } from '../api/types';

const STYLES: Record<Action, { label: string; classes: string; icon: string }> = {
  allow: { label: 'Allow', icon: '✓', classes: 'bg-allow/15 text-emerald-300 ring-allow/50' },
  alert: { label: 'Alert', icon: '!', classes: 'bg-alert/15 text-amber-300 ring-alert/50' },
  redact: { label: 'Redact', icon: '▒', classes: 'bg-redact/15 text-sky-300 ring-redact/50' },
  block: { label: 'Block', icon: '✕', classes: 'bg-block/15 text-red-300 ring-block/50' },
};

export const ACTION_LABELS: Record<Action, string> = {
  allow: 'Allow',
  alert: 'Alert',
  redact: 'Redact',
  block: 'Block',
};

/** Colour plus an icon and a text label, so the meaning never depends on colour alone. */
export function ActionBadge({ action, label }: { action: Action; label?: string }) {
  const style = STYLES[action];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${style.classes}`}
    >
      <span aria-hidden="true">{style.icon}</span>
      {label ?? style.label}
    </span>
  );
}

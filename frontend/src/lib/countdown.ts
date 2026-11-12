/** A countdown turns red below this many seconds. */
export const URGENT_SECONDS = 30;

/**
 * Whole seconds from `now` (epoch ms) until `expiresAt` (ISO 8601), rounded up
 * so "0:00" is only shown once the time is really up. Never negative. An
 * unreadable date counts as expired: the safe answer for an approval.
 */
export function secondsLeft(expiresAt: string, now: number): number {
  const end = Date.parse(expiresAt);
  if (Number.isNaN(end)) return 0;
  return Math.max(0, Math.ceil((end - now) / 1000));
}

/** 125 -> "2:05", 0 -> "Expired" */
export function formatCountdown(seconds: number): string {
  if (seconds <= 0) return 'Expired';
  const whole = Math.ceil(seconds);
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return `${minutes}:${String(rest).padStart(2, '0')}`;
}

/** True while there is still time, but not much. */
export function isUrgent(seconds: number): boolean {
  return seconds > 0 && seconds < URGENT_SECONDS;
}

import type { McpApproval } from '../api/types';

/**
 * When an approval was settled: the decision time, or the expiry time for an
 * approval that ran out without anyone deciding (the gateway leaves
 * decided_at empty for those).
 */
export function settledAt(approval: McpApproval): string {
  return approval.decided_at ?? approval.expires_at;
}

/** The approvals that are no longer pending, newest first, at most `limit`. */
export function recentDecisions(approvals: readonly McpApproval[], limit: number): McpApproval[] {
  return approvals
    .filter((approval) => approval.status !== 'pending')
    .map((approval, index) => ({ approval, index, time: Date.parse(settledAt(approval)) }))
    .sort((a, b) => {
      const byTime = (Number.isNaN(b.time) ? 0 : b.time) - (Number.isNaN(a.time) ? 0 : a.time);
      return byTime || a.index - b.index;
    })
    .slice(0, limit)
    .map((entry) => entry.approval);
}

/**
 * Pretty-print masked arguments. Objects and arrays are indented; anything
 * else (not JSON, or cut off by the gateway's length limit) is returned as
 * it is, so the approver always sees exactly what was stored.
 */
export function prettyArgs(text: string): { text: string; json: boolean } {
  // JSON.parse would round a number like 12345678901234567890 and show the
  // approver a different value than the one in the call: keep the raw text
  if (/\d{16,}/.test(text)) return { text, json: false };
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === 'object' && parsed !== null) {
      return { text: JSON.stringify(parsed, null, 2), json: true };
    }
  } catch {
    // not JSON
  }
  return { text, json: false };
}

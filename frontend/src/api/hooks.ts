import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { recentDecisions } from '../lib/approvals';
import {
  decideApproval,
  getApprovals,
  getHealth,
  getHistory,
  getMcpEvents,
  getMcpStats,
  getStats,
  inspectPrompt,
  sendChat,
} from './client';
import { useRefetchInterval } from './live';
import type { ApprovalDecision } from './types';

export const queryKeys = {
  health: ['health'] as const,
  stats: ['stats'] as const,
  history: (hours: number) => ['history', hours] as const,
  mcpEvents: (hours: number) => ['mcp-events', hours] as const,
  mcpEventsAll: ['mcp-events'] as const,
  mcpStats: ['mcp-stats'] as const,
  /** every approval query starts with this, so one invalidation refreshes them all */
  approvals: ['approvals'] as const,
  pendingApprovals: ['approvals', 'pending'] as const,
  recentApprovals: ['approvals', 'recent'] as const,
};

/**
 * Pending approvals are polled this often even when Live is paused: they
 * expire, and a human may be waiting on the screen.
 */
export const APPROVALS_POLL_MS = 3000;

/** How many decided approvals "Recent decisions" shows. */
export const RECENT_APPROVALS = 10;

export function useHealth() {
  const refetchInterval = useRefetchInterval();
  return useQuery({ queryKey: queryKeys.health, queryFn: getHealth, refetchInterval });
}

export function useStats() {
  const refetchInterval = useRefetchInterval();
  return useQuery({ queryKey: queryKeys.stats, queryFn: getStats, refetchInterval });
}

export function useHistory(hours: number) {
  const refetchInterval = useRefetchInterval();
  return useQuery({
    queryKey: queryKeys.history(hours),
    queryFn: () => getHistory(hours),
    refetchInterval,
  });
}

export function useInspect() {
  return useMutation({ mutationFn: inspectPrompt });
}

export function useChat() {
  return useMutation({ mutationFn: sendChat });
}

export function useMcpEvents(hours: number) {
  const refetchInterval = useRefetchInterval();
  return useQuery({
    queryKey: queryKeys.mcpEvents(hours),
    queryFn: () => getMcpEvents(hours),
    refetchInterval,
  });
}

export function useMcpStats() {
  const refetchInterval = useRefetchInterval();
  return useQuery({ queryKey: queryKeys.mcpStats, queryFn: getMcpStats, refetchInterval });
}

export function usePendingApprovals() {
  return useQuery({
    queryKey: queryKeys.pendingApprovals,
    queryFn: () => getApprovals('pending'),
    refetchInterval: APPROVALS_POLL_MS,
  });
}

/** The latest approved, denied and expired approvals, newest decision first. */
export function useRecentApprovals() {
  const refetchInterval = useRefetchInterval();
  return useQuery({
    queryKey: queryKeys.recentApprovals,
    queryFn: () => getApprovals(),
    select: (data) => recentDecisions(data.approvals, RECENT_APPROVALS),
    refetchInterval,
  });
}

/**
 * `onConflict` runs on a 409. It is called before the lists are refreshed: the
 * refresh removes the card that sent the decision, so a callback given to
 * `mutate()` would never fire.
 */
export function useDecideApproval(onConflict?: () => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: ApprovalDecision }) =>
      decideApproval(id, decision),
    // a conflict also means the lists on screen are out of date
    onSuccess: async (result) => {
      if (result.kind === 'conflict') onConflict?.();
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.approvals }),
        queryClient.invalidateQueries({ queryKey: queryKeys.mcpEventsAll }),
        queryClient.invalidateQueries({ queryKey: queryKeys.mcpStats }),
      ]);
    },
  });
}

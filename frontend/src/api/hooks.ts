import { useMutation, useQuery } from '@tanstack/react-query';

import { getHealth, getHistory, getStats, inspectPrompt, sendChat } from './client';
import { useRefetchInterval } from './live';

export const queryKeys = {
  health: ['health'] as const,
  stats: ['stats'] as const,
  history: (hours: number) => ['history', hours] as const,
};

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

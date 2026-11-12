import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';

/** How often stats, history and health are refetched while "Live" is on. */
export const REFETCH_INTERVAL_MS = 10_000;

interface LiveState {
  live: boolean;
  setLive: (value: boolean) => void;
}

const LiveContext = createContext<LiveState>({ live: true, setLive: () => undefined });

/** The global Live / Paused switch shown in the header. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [live, setLive] = useState(true);
  const value = useMemo(() => ({ live, setLive }), [live]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  return useContext(LiveContext);
}

/** The `refetchInterval` value for the current Live state. */
export function useRefetchInterval(): number | false {
  return useLive().live ? REFETCH_INTERVAL_MS : false;
}

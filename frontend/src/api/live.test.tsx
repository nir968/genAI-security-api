import { act, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';

import { LiveProvider, REFETCH_INTERVAL_MS, useLive, useRefetchInterval } from './live';

const wrapper = ({ children }: { children: ReactNode }) => <LiveProvider>{children}</LiveProvider>;

describe('live state', () => {
  it('starts live, with a 10 second refetch interval', () => {
    const { result } = renderHook(() => ({ live: useLive(), interval: useRefetchInterval() }), { wrapper });
    expect(result.current.live.live).toBe(true);
    expect(result.current.interval).toBe(REFETCH_INTERVAL_MS);
    expect(REFETCH_INTERVAL_MS).toBe(10_000);
  });

  it('turns refetching off when paused', () => {
    const { result } = renderHook(() => ({ live: useLive(), interval: useRefetchInterval() }), { wrapper });
    act(() => result.current.live.setLive(false));
    expect(result.current.interval).toBe(false);
  });

  it('defaults to live without a provider', () => {
    const { result } = renderHook(() => useLive());
    expect(result.current.live).toBe(true);
    expect(() => result.current.setLive(false)).not.toThrow();
  });
});

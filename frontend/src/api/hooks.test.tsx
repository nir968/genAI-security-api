import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderHook, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { server } from '../test/server';
import { APPROVALS_POLL_MS, queryKeys, useDecideApproval, usePendingApprovals } from './hooks';
import { LiveProvider } from './live';

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <LiveProvider>{children}</LiveProvider>
    </QueryClientProvider>
  );
  return { client, invalidate, wrapper };
}

describe('useDecideApproval', () => {
  it('refreshes the approval lists, the MCP events and the MCP stats after a decision', async () => {
    const { invalidate, wrapper } = setup();
    const { result } = renderHook(() => useDecideApproval(), { wrapper });
    result.current.mutate({ id: 'abc', decision: 'approve' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const keys = invalidate.mock.calls.map(([filters]) => filters?.queryKey);
    expect(keys).toContainEqual(queryKeys.approvals);
    expect(keys).toContainEqual(queryKeys.mcpEventsAll);
    expect(keys).toContainEqual(queryKeys.mcpStats);
  });

  it('calls onConflict and still refreshes the lists on a 409', async () => {
    const { invalidate, wrapper } = setup();
    const onConflict = vi.fn();
    const { result } = renderHook(() => useDecideApproval(onConflict), { wrapper });
    result.current.mutate({ id: 'already-decided', decision: 'deny' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(onConflict).toHaveBeenCalledTimes(1);
    expect(invalidate).toHaveBeenCalledTimes(3);
  });

  it('does not call onConflict, or refresh anything, when the request fails', async () => {
    server.use(http.post('/api/mcp/approvals/:id/decision', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    const { invalidate, wrapper } = setup();
    const onConflict = vi.fn();
    const { result } = renderHook(() => useDecideApproval(onConflict), { wrapper });
    result.current.mutate({ id: 'x', decision: 'deny' });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(onConflict).not.toHaveBeenCalled();
    expect(invalidate).not.toHaveBeenCalled();
  });

  it('works without an onConflict callback', async () => {
    const { wrapper } = setup();
    const { result } = renderHook(() => useDecideApproval(), { wrapper });
    result.current.mutate({ id: 'already-decided', decision: 'deny' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
  });
});

describe('usePendingApprovals', () => {
  it('polls every 3 seconds, whatever the Live toggle says', () => {
    expect(APPROVALS_POLL_MS).toBe(3000);
  });

  it('loads the pending approvals', async () => {
    const { wrapper } = setup();
    const { result } = renderHook(() => usePendingApprovals(), { wrapper });
    await waitFor(() => expect(result.current.data?.approvals).toHaveLength(2));
  });
});

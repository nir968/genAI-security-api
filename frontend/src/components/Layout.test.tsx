import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';

import { makeApproval } from '../test/fixtures';
import { server } from '../test/server';
import { renderApp } from '../test/utils';

describe('Layout', () => {
  it('shows the app name, the navigation and the gateway status', async () => {
    renderApp('/playground');
    expect(screen.getByRole('heading', { name: 'GenAI Security Gateway', level: 1 })).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(nav).toHaveTextContent('Overview');
    expect(nav).toHaveTextContent('Events');
    expect(nav).toHaveTextContent('Playground');
    expect(await screen.findByText('Online')).toBeInTheDocument();
  });

  it('marks the current page in the navigation', async () => {
    renderApp('/events');
    expect(screen.getByRole('link', { name: 'Events' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current');
  });

  it('navigates between pages', async () => {
    const user = userEvent.setup();
    renderApp('/playground');
    await user.click(screen.getByRole('link', { name: 'Events' }));
    expect(await screen.findByRole('heading', { name: 'Events', level: 2 })).toBeInTheDocument();
  });

  it('sends unknown paths to the overview', async () => {
    renderApp('/no-such-page');
    expect(await screen.findByRole('group', { name: 'Total requests' })).toBeInTheDocument();
  });

  it('shows Offline and the banner when the gateway does not answer', async () => {
    server.use(http.get('/api/health', () => HttpResponse.error()));
    renderApp('/playground');
    expect(await screen.findByText('Offline')).toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent(/api offline/i);
  });

  it('has no banner while the gateway is healthy', async () => {
    renderApp('/playground');
    await screen.findByText('Online');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('toggles between Live and Paused', async () => {
    const user = userEvent.setup();
    renderApp('/playground');
    const toggle = screen.getByRole('switch', { name: 'Live' });
    expect(toggle).toBeChecked();
    await user.click(toggle);
    expect(screen.getByRole('switch', { name: 'Paused' })).not.toBeChecked();
    await user.click(screen.getByRole('switch', { name: 'Paused' }));
    expect(screen.getByRole('switch', { name: 'Live' })).toBeChecked();
  });

  it('polls every 10 seconds while Live and stops when Paused', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let calls = 0;
      server.use(
        http.get('/api/health', () => {
          calls += 1;
          return HttpResponse.json({ status: 'ok' });
        }),
      );
      const user = userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });
      renderApp('/playground');
      await waitFor(() => expect(calls).toBe(1));

      await act(() => vi.advanceTimersByTimeAsync(10_000));
      await waitFor(() => expect(calls).toBe(2));

      await user.click(screen.getByRole('switch', { name: 'Live' }));
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('has Agents and Approvals in the navigation', () => {
    renderApp('/playground');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(nav).toHaveTextContent('Agents');
    expect(nav).toHaveTextContent('Approvals');
  });

  it('shows the pending count next to Approvals on every page', async () => {
    for (const path of ['/', '/events', '/playground']) {
      const { unmount } = renderApp(path);
      expect(await screen.findByLabelText('2 pending approvals')).toHaveTextContent('2');
      expect(screen.getByRole('link', { name: /Approvals/ })).toContainElement(screen.getByLabelText('2 pending approvals'));
      unmount();
    }
  });

  it('uses the singular for one pending approval', async () => {
    server.use(http.get('/api/mcp/approvals', () => HttpResponse.json({ approvals: [makeApproval()] })));
    renderApp('/events');
    expect(await screen.findByLabelText('1 pending approval')).toBeInTheDocument();
  });

  it('hides the badge at zero', async () => {
    server.use(http.get('/api/mcp/approvals', () => HttpResponse.json({ approvals: [] })));
    renderApp('/events');
    await screen.findByText('Online');
    expect(screen.queryByLabelText(/pending approval/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Approvals' })).toBeInTheDocument();
  });

  it('shows 99+ for a very long queue but keeps the real number in the label', async () => {
    const many = Array.from({ length: 120 }, (_, i) => makeApproval({ id: `id-${i}` }));
    server.use(http.get('/api/mcp/approvals', () => HttpResponse.json({ approvals: many })));
    renderApp('/events');
    const badge = await screen.findByLabelText('120 pending approvals');
    expect(badge).toHaveTextContent('99+');
  });

  it('keeps counting while Live is paused, because approvals expire', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'], shouldAdvanceTime: true });
    try {
      let count = 1;
      server.use(
        http.get('/api/mcp/approvals', () =>
          HttpResponse.json({ approvals: Array.from({ length: count }, (_, i) => makeApproval({ id: `p${i}` })) }),
        ),
      );
      renderApp('/playground');
      expect(await screen.findByLabelText('1 pending approval')).toBeInTheDocument();
      // pause Live: the 10 s refreshes stop, the 3 s approvals poll does not
      act(() => screen.getByRole('switch', { name: 'Live' }).click());
      count = 3;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3500);
      });
      expect(await screen.findByLabelText('3 pending approvals')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

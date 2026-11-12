import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { McpApproval } from '../api/types';
import { makeApproval, secondsFromNow } from '../test/fixtures';
import { server } from '../test/server';
import { ApprovalCard, Countdown } from './ApprovalCard';

function renderCard(approval: McpApproval, onConflict = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ApprovalCard approval={approval} onConflict={onConflict} />
    </QueryClientProvider>,
  );
  return { onConflict };
}

function captureDecisions() {
  const sent: { id: string; decision: string }[] = [];
  server.use(
    http.post('/api/mcp/approvals/:id/decision', async ({ params, request }) => {
      const body = (await request.json()) as { decision: string };
      sent.push({ id: String(params.id), decision: body.decision });
      return HttpResponse.json(makeApproval({ id: String(params.id), status: 'approved' }));
    }),
  );
  return sent;
}

afterEach(() => vi.useRealTimers());

describe('Countdown', () => {
  it('ticks every second, turns red under 30 seconds, and says Expired at zero', () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'));
    render(<Countdown expiresAt="2026-06-10T12:00:35Z" />);

    const view = () => screen.getByText(/\d:\d\d|Expired/);
    expect(view()).toHaveTextContent('0:35');
    expect(view()).toHaveAttribute('data-urgent', 'false');
    expect(view()).not.toHaveClass('text-red-300');

    act(() => vi.advanceTimersByTime(5000));
    expect(view()).toHaveTextContent('0:30');
    expect(view()).toHaveAttribute('data-urgent', 'false');

    act(() => vi.advanceTimersByTime(1000));
    expect(view()).toHaveTextContent('0:29');
    expect(view()).toHaveAttribute('data-urgent', 'true');
    expect(view()).toHaveClass('text-red-300');

    act(() => vi.advanceTimersByTime(28_000));
    expect(view()).toHaveTextContent('0:01');

    act(() => vi.advanceTimersByTime(1000));
    expect(view()).toHaveTextContent('Expired');
    expect(view()).toHaveAttribute('data-urgent', 'false');
    expect(view()).toHaveClass('text-red-300');
  });

  it('stops its timer when it unmounts', () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    const { unmount } = render(<Countdown expiresAt={secondsFromNow(60)} />);
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('ApprovalCard', () => {
  it('shows tool, server, reason, created time, countdown and pretty-printed arguments', () => {
    renderCard(makeApproval({ expires_at: secondsFromNow(100) }));
    expect(screen.getByRole('heading', { name: 'send_email' })).toBeInTheDocument();
    expect(screen.getByText('corp-docs')).toBeInTheDocument();
    expect(screen.getByText('Recipient outside the allowed domains')).toBeInTheDocument();
    expect(screen.getByText(/^\d:\d\d$/)).toBeInTheDocument();
    const args = screen.getByLabelText('Arguments');
    expect(args.textContent).toBe(
      '{\n  "to": "b***@example.org",\n  "subject": "Report",\n  "body": "Q3 numbers attached"\n}',
    );
  });

  it('highlights masks and invisible-character markers in the arguments', () => {
    renderCard(makeApproval({ args_masked: '{"to": "d***@example.org", "subject": "Hi<U+200B>x"}' }));
    const args = screen.getByLabelText('Arguments');
    const hidden = args.querySelector('mark[data-hidden-char]');
    expect(hidden).toHaveTextContent('<U+200B>');
    expect(hidden).toHaveAttribute('title', 'Invisible character');
    expect(args.querySelectorAll('mark')).toHaveLength(2);
    expect(screen.getByText('d***@example.org').tagName).toBe('MARK');
  });

  it('shows arguments that are not JSON exactly as stored', () => {
    renderCard(makeApproval({ args_masked: 'to=b***@example.org subject=Hi' }));
    expect(screen.getByLabelText('Arguments').textContent).toBe('to=b***@example.org subject=Hi');
    expect(screen.getByText(/shown as sent/)).toBeInTheDocument();
  });

  it('says so when there is no reason', () => {
    renderCard(makeApproval({ reason: '' }));
    expect(screen.getByText('No reason given')).toBeInTheDocument();
  });

  it('approve needs a second click on "Confirm send" before anything is sent', async () => {
    const sent = captureDecisions();
    const user = userEvent.setup();
    renderCard(makeApproval({ id: 'one' }));

    await user.click(screen.getByRole('button', { name: 'Approve' }));
    expect(sent).toEqual([]);
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Confirm send' }));
    await waitFor(() => expect(sent).toEqual([{ id: 'one', decision: 'approve' }]));
  });

  it('cancel goes back to the Approve button without sending', async () => {
    const sent = captureDecisions();
    const user = userEvent.setup();
    renderCard(makeApproval());
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm send' })).not.toBeInTheDocument();
    expect(sent).toEqual([]);
  });

  it('deny sends at once, with no confirmation', async () => {
    const sent = captureDecisions();
    const user = userEvent.setup();
    renderCard(makeApproval({ id: 'two' }));
    await user.click(screen.getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(sent).toEqual([{ id: 'two', decision: 'deny' }]));
  });

  it('deny while the confirmation is open closes it and sends a deny', async () => {
    const sent = captureDecisions();
    const user = userEvent.setup();
    renderCard(makeApproval({ id: 'three' }));
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    await user.click(screen.getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(sent).toEqual([{ id: 'three', decision: 'deny' }]));
    expect(screen.queryByRole('button', { name: 'Confirm send' })).not.toBeInTheDocument();
  });

  it('disables both buttons while the request is in flight', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    server.use(
      http.post('/api/mcp/approvals/:id/decision', async () => {
        await gate;
        return HttpResponse.json(makeApproval({ status: 'denied' }));
      }),
    );
    const user = userEvent.setup();
    renderCard(makeApproval());
    await user.click(screen.getByRole('button', { name: 'Deny' }));

    expect(await screen.findByRole('status')).toHaveTextContent('Sending decision');
    expect(screen.getByRole('button', { name: 'Deny' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled();

    release();
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
  });

  it('tells the page about a 409', async () => {
    const user = userEvent.setup();
    const { onConflict } = renderCard(makeApproval({ id: 'already-decided' }));
    await user.click(screen.getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(onConflict).toHaveBeenCalledTimes(1));
  });

  it('shows an error and re-enables the buttons when the request fails', async () => {
    server.use(http.post('/api/mcp/approvals/:id/decision', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    const user = userEvent.setup();
    const { onConflict } = renderCard(makeApproval());
    await user.click(screen.getByRole('button', { name: 'Deny' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not send the decision');
    expect(screen.getByRole('button', { name: 'Deny' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();
    expect(onConflict).not.toHaveBeenCalled();
  });

  it('shows Expired and disables the buttons at zero, without waiting for a poll', () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'));
    renderCard(makeApproval({ expires_at: '2026-06-10T12:00:03Z' }));
    expect(screen.getByRole('button', { name: 'Approve' })).toBeEnabled();

    act(() => vi.advanceTimersByTime(3000));
    expect(screen.getAllByText('Expired').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Deny' })).toBeDisabled();
  });

  it('cannot confirm an approval that ran out while the confirmation was open', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'));
    renderCard(makeApproval({ expires_at: '2026-06-10T12:00:05Z' }));
    act(() => screen.getByRole('button', { name: 'Approve' }).click());
    expect(screen.getByRole('button', { name: 'Confirm send' })).toBeEnabled();
    act(() => vi.advanceTimersByTime(5000));
    expect(screen.getByRole('button', { name: 'Confirm send' })).toBeDisabled();
  });
});

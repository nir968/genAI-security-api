import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import type { McpApproval } from '../api/types';
import { makeApproval, sampleDecided, samplePending } from '../test/fixtures';
import { server } from '../test/server';
import { renderApp } from '../test/utils';

function serveApprovals(pending: McpApproval[], decided: McpApproval[] = sampleDecided()) {
  server.use(
    http.get('/api/mcp/approvals', ({ request }) => {
      const status = new URL(request.url).searchParams.get('status');
      const all = [...pending, ...decided];
      return HttpResponse.json({
        approvals: status === null ? all : all.filter((approval) => approval.status === status),
      });
    }),
  );
}

describe('Approvals page', () => {
  it('renders one card per pending approval', async () => {
    renderApp('/approvals');
    expect(await screen.findAllByRole('article')).toHaveLength(2);
    const [first, second] = screen.getAllByRole('article');
    expect(within(first as HTMLElement).getByRole('heading', { name: 'send_email' })).toBeInTheDocument();
    expect(within(first as HTMLElement).getByText('Recipient outside the allowed domains')).toBeInTheDocument();
    expect(within(second as HTMLElement).getByText(/c\*\*\*@example\.net/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Pending/ })).toHaveTextContent('Pending (2)');
  });

  it('highlights an invisible character in the arguments', async () => {
    renderApp('/approvals');
    await screen.findAllByRole('article');
    const marks = document.querySelectorAll('mark[data-hidden-char]');
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('<U+200B>');
  });

  it('shows the empty state when nothing is pending', async () => {
    serveApprovals([]);
    renderApp('/approvals');
    expect(await screen.findByText('No pending approvals.')).toBeInTheDocument();
    expect(
      screen.getByText('When an agent tries a sensitive action, it will appear here.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('article')).not.toBeInTheDocument();
  });

  it('lists recent decisions with a status badge and the decision time', async () => {
    renderApp('/approvals');
    const table = await screen.findByRole('table', { name: /Recent approval decisions/ });
    const rows = within(table).getAllByRole('row').slice(1);
    // newest decision first: denied (9 min ago), approved (29), expired (48 min ago, expiry time)
    ['Denied', 'Approved', 'Expired'].forEach((label, i) => {
      expect(within(rows[i] as HTMLElement).getByText(label)).toBeInTheDocument();
    });
    expect(within(rows[0] as HTMLElement).getByText('send_email')).toBeInTheDocument();
    expect((rows[0] as HTMLElement).querySelector('time')).toHaveAttribute('dateTime');
  });

  it('does not list pending approvals under recent decisions', async () => {
    renderApp('/approvals');
    const table = await screen.findByRole('table', { name: /Recent approval decisions/ });
    expect(within(table).queryByText('Pending')).not.toBeInTheDocument();
    expect(within(table).getAllByRole('row')).toHaveLength(4);
  });

  it('shows an empty note when there are no decisions yet', async () => {
    serveApprovals(samplePending(), []);
    renderApp('/approvals');
    expect(await screen.findByText('No decisions yet')).toBeInTheDocument();
  });

  it('shows errors for both sections when the gateway fails', async () => {
    server.use(http.get('/api/mcp/approvals', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/approvals');
    expect(await screen.findByText('Could not load pending approvals from the gateway.')).toBeInTheDocument();
    expect(await screen.findByText('Could not load recent decisions from the gateway.')).toBeInTheDocument();
  });

  it('approving needs confirmation, then calls the API', async () => {
    const sent: { id: string; decision: string }[] = [];
    server.use(
      http.post('/api/mcp/approvals/:id/decision', async ({ params, request }) => {
        const body = (await request.json()) as { decision: string };
        sent.push({ id: String(params.id), decision: body.decision });
        return HttpResponse.json(makeApproval({ status: 'approved' }));
      }),
    );
    const user = userEvent.setup();
    renderApp('/approvals');
    const [card] = await screen.findAllByRole('article');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Approve' }));
    expect(sent).toEqual([]);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Confirm send' }));
    await waitFor(() => expect(sent).toEqual([{ id: samplePending()[0]?.id, decision: 'approve' }]));
  });

  it('after a decision the pending list is refetched and the card goes away', async () => {
    let decided = false;
    server.use(
      http.get('/api/mcp/approvals', ({ request }) => {
        const status = new URL(request.url).searchParams.get('status');
        const pending = decided ? samplePending().slice(1) : samplePending();
        return HttpResponse.json({ approvals: status === 'pending' ? pending : sampleDecided() });
      }),
      http.post('/api/mcp/approvals/:id/decision', () => {
        decided = true;
        return HttpResponse.json(makeApproval({ status: 'denied' }));
      }),
    );
    const user = userEvent.setup();
    renderApp('/approvals');
    const [card] = await screen.findAllByRole('article');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(1));
  });

  it('denying calls the API with no confirmation', async () => {
    const sent: string[] = [];
    server.use(
      http.post('/api/mcp/approvals/:id/decision', async ({ request }) => {
        sent.push(((await request.json()) as { decision: string }).decision);
        return HttpResponse.json(makeApproval({ status: 'denied' }));
      }),
    );
    const user = userEvent.setup();
    renderApp('/approvals');
    const [card] = await screen.findAllByRole('article');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(sent).toEqual(['deny']));
  });

  it('a 409 shows "already decided or expired", even though the card goes away', async () => {
    const pending = [makeApproval({ id: 'already-decided' })];
    let decided = false;
    server.use(
      http.get('/api/mcp/approvals', ({ request }) => {
        const status = new URL(request.url).searchParams.get('status');
        return HttpResponse.json({
          approvals: status === 'pending' ? (decided ? [] : pending) : sampleDecided(),
        });
      }),
      http.post('/api/mcp/approvals/:id/decision', () => {
        decided = true;
        return HttpResponse.json(
          { detail: { error: 'Approval is not pending', status: 'approved' } },
          { status: 409 },
        );
      }),
    );
    const user = userEvent.setup();
    renderApp('/approvals');
    await user.click(await screen.findByRole('button', { name: 'Deny' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('This request was already decided or has expired');
    await waitFor(() => expect(screen.queryByRole('article')).not.toBeInTheDocument());
    expect(screen.getByRole('alert')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('says plainly that anyone who can open the page can approve', async () => {
    renderApp('/approvals');
    expect(await screen.findByText(/anyone who can open this page can approve/i)).toBeInTheDocument();
  });
});

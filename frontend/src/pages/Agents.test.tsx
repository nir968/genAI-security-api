import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import type { McpEvent } from '../api/types';
import { makeMcpEvent, minutesAgo } from '../test/fixtures';
import { server } from '../test/server';
import { renderApp } from '../test/utils';
import { README_URL } from './Agents';

const card = (name: string) => screen.getByRole('group', { name });

async function bodyRows() {
  const table = await screen.findByRole('table', { name: /Agent security events/ });
  return within(table).getAllByRole('row').slice(1);
}

async function eventLabels(): Promise<string[]> {
  const labels = [
    'Tool definition changed',
    'Approval granted',
    'Approval requested',
    'Result redacted',
    'Injection removed',
    'Arguments blocked (DLP)',
    'Tool not allowed',
    'Tool call allowed',
  ];
  return (await bodyRows()).map(
    (row) => labels.find((label) => within(row).queryByText(label)) ?? '?',
  );
}

function serveEvents(events: McpEvent[]) {
  server.use(http.get('/api/mcp/events', () => HttpResponse.json({ events })));
}

describe('Agents page: stat cards', () => {
  it('shows the values from /mcp/stats', async () => {
    renderApp('/agents');
    expect(await within(await screen.findByRole('group', { name: 'Tool calls allowed' })).findByText('15')).toBeInTheDocument();
    expect(within(card('Calls blocked')).getByText('6')).toBeInTheDocument(); // 2 + 3 + 1
    expect(within(card('Injections removed')).getByText('3')).toBeInTheDocument();
    expect(within(card('Results redacted')).getByText('4')).toBeInTheDocument();
    expect(within(card('Tool poisoning')).getByText('3')).toBeInTheDocument(); // 1 + 2
    const approvals = card('Approvals');
    expect(within(approvals).getByText('Granted').nextSibling).toHaveTextContent('3');
    expect(within(approvals).getByText('Denied').nextSibling).toHaveTextContent('1');
    expect(within(approvals).getByText('Expired').nextSibling).toHaveTextContent('1');
  });

  it('shows dashes when /mcp/stats fails', async () => {
    server.use(http.get('/api/mcp/stats', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/agents');
    expect(await within(card('Tool calls allowed')).findByText('—')).toBeInTheDocument();
    expect(within(card('Approvals')).getByText('—')).toBeInTheDocument();
  });
});

describe('Agents page: events table', () => {
  it('lists events newest first with badge, tool, decision, data types and a details preview', async () => {
    renderApp('/agents');
    expect(await eventLabels()).toEqual([
      'Tool definition changed',
      'Approval granted',
      'Approval requested',
      'Result redacted',
      'Injection removed',
      'Arguments blocked (DLP)',
      'Tool not allowed',
      'Tool call allowed', // two of them: list_documents and read_document
      'Tool call allowed',
    ]);
    const rows = await bodyRows();
    expect(rows).toHaveLength(9);
    const redacted = within(rows[3] as HTMLElement);
    expect(redacted.getByText('CREDIT_CARD')).toBeInTheDocument();
    expect(redacted.getByText('IBAN')).toBeInTheDocument();
    expect(redacted.getByText('redact')).toBeInTheDocument();
    const changed = within(rows[0] as HTMLElement);
    expect(changed.getByText('send_email')).toBeInTheDocument();
    expect(changed.getByText('quarantine')).toBeInTheDocument();
  });

  it('colours each category differently and always shows text too', async () => {
    renderApp('/agents');
    const rows = await bodyRows();
    const classOf = (row: HTMLElement, label: string) => within(row).getByText(label).closest('span')?.className ?? '';
    expect(classOf(rows[8] as HTMLElement, 'Tool call allowed')).toContain('text-emerald-300');
    expect(classOf(rows[6] as HTMLElement, 'Tool not allowed')).toContain('text-red-300');
    expect(classOf(rows[3] as HTMLElement, 'Result redacted')).toContain('text-sky-300');
    expect(classOf(rows[0] as HTMLElement, 'Tool definition changed')).toContain('text-amber-300');
    expect(classOf(rows[1] as HTMLElement, 'Approval granted')).toContain('text-violet-300');
  });

  it('expands and collapses the details of a row', async () => {
    const user = userEvent.setup();
    renderApp('/agents');
    const rows = await bodyRows();
    const toggle = within(rows[0] as HTMLElement).getByRole('button');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const detail = document.getElementById(toggle.getAttribute('aria-controls') ?? '');
    expect(detail).toHaveTextContent('pinned 87d7b548b14d, now af86edef421f; call blocked');
    expect(detail).toHaveTextContent('Server corp-docs');
    await user.click(toggle);
    expect(document.getElementById(toggle.getAttribute('aria-controls') ?? '')).toBeNull();
  });

  it('highlights masks and hidden-character markers in the details', async () => {
    serveEvents([
      makeMcpEvent({
        id: 1,
        timestamp: minutesAgo(1),
        details: 'recipient d***@example.org subject Hi<U+200B>',
      }),
    ]);
    const user = userEvent.setup();
    renderApp('/agents');
    const [row] = await bodyRows();
    await user.click(within(row as HTMLElement).getByRole('button'));
    expect(document.querySelectorAll('mark[data-hidden-char]')).toHaveLength(1);
    expect(screen.getByText('d***@example.org').tagName).toBe('MARK');
  });

  it('shows a dash instead of a button for an event with no details or tool', async () => {
    serveEvents([makeMcpEvent({ id: 1, timestamp: minutesAgo(1), tool_name: null, details: '' })]);
    renderApp('/agents');
    const [row] = await bodyRows();
    expect(within(row as HTMLElement).queryByRole('button')).not.toBeInTheDocument();
    expect(within(row as HTMLElement).getAllByText('—')).toHaveLength(2);
  });

  it('filters by event category', async () => {
    const user = userEvent.setup();
    renderApp('/agents');
    await bodyRows();
    await user.selectOptions(screen.getByLabelText('Event type'), 'blocked');
    expect(await eventLabels()).toEqual(['Arguments blocked (DLP)', 'Tool not allowed']);
    await user.selectOptions(screen.getByLabelText('Event type'), 'approval');
    expect(await eventLabels()).toEqual(['Approval granted', 'Approval requested']);
    await user.selectOptions(screen.getByLabelText('Event type'), 'all');
    expect(await bodyRows()).toHaveLength(9);
  });

  it('offers the tools that appear in the events and filters by tool', async () => {
    const user = userEvent.setup();
    renderApp('/agents');
    await bodyRows();
    const select = screen.getByLabelText('Tool');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'All tools',
      'delete_everything',
      'list_documents',
      'read_document',
      'send_email',
    ]);
    await user.selectOptions(select, 'delete_everything');
    expect(await eventLabels()).toEqual(['Tool not allowed']);
  });

  it('searches the details, the tool and the data types', async () => {
    const user = userEvent.setup();
    renderApp('/agents');
    await bodyRows();
    const search = screen.getByLabelText('Search');
    await user.type(search, 'allowlist');
    expect(await eventLabels()).toEqual(['Tool not allowed']);
    await user.clear(search);
    await user.type(search, 'iban');
    expect(await eventLabels()).toEqual(['Result redacted']);
    await user.clear(search);
    await user.type(search, 'zzz');
    expect(await screen.findByText('No events match')).toBeInTheDocument();
  });

  it('asks the gateway for the selected time range', async () => {
    const asked: string[] = [];
    server.use(
      http.get('/api/mcp/events', ({ request }) => {
        asked.push(new URL(request.url).searchParams.get('hours') ?? '');
        return HttpResponse.json({ events: [] });
      }),
    );
    const user = userEvent.setup();
    renderApp('/agents');
    await screen.findByText('No events match');
    expect(asked).toEqual(['24']);
    await user.click(screen.getByRole('button', { name: '7 days' }));
    await screen.findByText('No events match');
    expect(asked).toContain('168');
    await user.click(screen.getByRole('button', { name: '1 hour' }));
    await screen.findByText('No events match');
    expect(asked).toContain('1');
  });

  it('paginates 25 events per page', async () => {
    const many = Array.from({ length: 60 }, (_, i) =>
      makeMcpEvent({ id: i + 1, timestamp: minutesAgo(i + 1), tool_name: `tool_${String(i + 1).padStart(2, '0')}` }),
    );
    serveEvents(many);
    const user = userEvent.setup();
    renderApp('/agents');
    expect(await bodyRows()).toHaveLength(25);
    expect(screen.getByText(/Page 1 of 3 · 60 events/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument();
    expect(within((await bodyRows())[0] as HTMLElement).getByText('tool_26')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await bodyRows()).toHaveLength(10);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });

  it('goes back to page 1 when a filter changes', async () => {
    const many = Array.from({ length: 60 }, (_, i) => makeMcpEvent({ id: i + 1, timestamp: minutesAgo(i + 1) }));
    serveEvents(many);
    const user = userEvent.setup();
    renderApp('/agents');
    await bodyRows();
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText('Event type'), 'allowed');
    expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument();
  });

  it('notes when the newest events were cut off by the request limit', async () => {
    serveEvents(Array.from({ length: 2000 }, (_, i) => makeMcpEvent({ id: i + 1, timestamp: minutesAgo(1) })));
    renderApp('/agents');
    expect(await screen.findByText(/newest 2000 loaded/)).toBeInTheDocument();
  });

  it('shows the empty state and the error notice', async () => {
    serveEvents([]);
    const { unmount } = renderApp('/agents');
    expect(await screen.findByText('No events match')).toBeInTheDocument();
    unmount();

    server.use(http.get('/api/mcp/events', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/agents');
    expect(await screen.findByText('Could not load agent events from the gateway.')).toBeInTheDocument();
  });
});

describe('Agents page: how it works', () => {
  it('explains the five controls and links to the README', async () => {
    renderApp('/agents');
    const summary = await screen.findByText('How the proxy protects agents');
    const details = summary.closest('details') as HTMLDetailsElement;
    expect(details.open).toBe(false);
    for (const name of ['Allowlist', 'Tool pinning', 'Argument DLP', 'Human approval', 'Result scanning']) {
      expect(within(details).getByText(name, { exact: false })).toBeInTheDocument();
    }
    const link = within(details).getByRole('link', { name: /README/ });
    expect(link).toHaveAttribute('href', README_URL);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toContain('noreferrer');

    await userEvent.setup().click(summary);
    expect(details.open).toBe(true);
  });
});

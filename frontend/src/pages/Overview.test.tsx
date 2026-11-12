import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { server } from '../test/server';
import { renderApp } from '../test/utils';

const card = (name: string) => screen.getByRole('group', { name });

describe('Overview', () => {
  it('renders the stat values from /stats', async () => {
    renderApp('/');
    expect(await within(await screen.findByRole('group', { name: 'Total requests' })).findByText('1,234')).toBeInTheDocument();
    expect(within(card('Injections blocked')).getByText('17')).toBeInTheDocument();
    expect(within(card('Data leaks prevented')).getByText('42')).toBeInTheDocument();
    expect(within(card('Redactions')).getByText('9')).toBeInTheDocument();
    expect(within(card('Alerts')).getByText('5')).toBeInTheDocument();
  });

  it('shows loading placeholders before the data arrives', async () => {
    renderApp('/');
    const total = await screen.findByRole('group', { name: 'Total requests' });
    expect(within(total).queryByText('1,234')).not.toBeInTheDocument();
    expect(await within(total).findByText('1,234')).toBeInTheDocument();
  });

  it('shows the offline banner and dashes when /api/stats fails', async () => {
    server.use(http.get('/api/stats', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/');
    expect(await screen.findByRole('alert')).toHaveTextContent(/api offline/i);
    expect(await within(card('Total requests')).findByText('—')).toBeInTheDocument();
  });

  it('shows the offline banner when the network is down', async () => {
    server.use(http.get('/api/stats', () => HttpResponse.error()));
    renderApp('/');
    expect(await screen.findByRole('alert')).toHaveTextContent(/api offline/i);
  });

  it('shows the empty states when there are no events', async () => {
    server.use(http.get('/api/history', () => HttpResponse.json({ records: [] })));
    renderApp('/');
    expect(await screen.findByText('No events in this window')).toBeInTheDocument();
    expect(screen.getByText('No sensitive data in this window')).toBeInTheDocument();
  });

  it('shows an error notice for the charts when /history fails', async () => {
    server.use(http.get('/api/history', () => HttpResponse.json({ detail: 'boom' }, { status: 500 })));
    renderApp('/');
    expect(await screen.findByText('Could not load activity from the gateway.')).toBeInTheDocument();
    expect(screen.getByText('Could not load data types from the gateway.')).toBeInTheDocument();
  });

  it('counts findings per data type for the bar chart', async () => {
    renderApp('/');
    const table = await screen.findByRole('table', { name: 'Events per sensitive data type', hidden: true });
    const rows = within(table).getAllByRole('row', { hidden: true }).slice(1);
    expect(rows.map((row) => row.textContent)).toEqual([
      'CREDIT_CARD2', // blocked input + redacted output
      'AWS_ACCESS_KEY1',
      'EMAIL1',
      'IBAN1',
    ]);
  });

  it('stacks the activity by action', async () => {
    renderApp('/');
    const table = await screen.findByRole('table', { name: 'Events per time bucket by action', hidden: true });
    const body = within(table).getAllByRole('row', { hidden: true }).slice(1);
    // columns: time, allow, alert, redact, block
    const sums = [0, 0, 0, 0];
    for (const row of body) {
      within(row)
        .getAllByRole('cell', { hidden: true })
        .forEach((cell, i) => {
          sums[i] = (sums[i] ?? 0) + Number(cell.textContent);
        });
    }
    expect(sums).toEqual([2, 1, 2, 2]);
  });

  it('asks the gateway for the selected time range', async () => {
    const asked: string[] = [];
    server.use(
      http.get('/api/history', ({ request }) => {
        asked.push(new URL(request.url).searchParams.get('hours') ?? '');
        return HttpResponse.json({ records: [] });
      }),
    );
    const user = userEvent.setup();
    renderApp('/');
    await screen.findByText('No events in this window');
    expect(asked).toEqual(['24']);

    await user.click(screen.getByRole('button', { name: '7 days' }));
    await screen.findByText('No events in this window');
    expect(asked).toContain('168');
    expect(screen.getByRole('button', { name: '7 days' })).toHaveAttribute('aria-pressed', 'true');

    await user.click(screen.getByRole('button', { name: '1 hour' }));
    await screen.findByText('No events in this window');
    expect(asked).toContain('1');
  });
});

import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { App, createQueryClient } from './App';

describe('App', () => {
  it('renders the overview at the root URL with real providers and a browser router', async () => {
    window.history.pushState({}, '', '/');
    render(<App />);
    const total = await screen.findByRole('group', { name: 'Total requests' });
    expect(await within(total).findByText('1,234')).toBeInTheDocument();
  });

  it('creates a query client that retries once', () => {
    expect(createQueryClient().getDefaultOptions().queries?.retry).toBe(1);
  });
});

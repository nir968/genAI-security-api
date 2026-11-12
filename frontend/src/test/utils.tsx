import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';

import { LiveProvider } from '../api/live';
import { AppRoutes } from '../App';

/** The whole app at `path`, with a query client that does not retry or cache. */
export function renderApp(path = '/') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <LiveProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </LiveProvider>
    </QueryClientProvider>,
  );
}

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { lazy, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';

import { LiveProvider } from './api/live';
import { Layout } from './components/Layout';
import { Events } from './pages/Events';
import { Playground } from './pages/Playground';

// the overview is the only page that uses the (large) charting library
const Overview = lazy(() => import('./pages/Overview').then((m) => ({ default: m.Overview })));

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: 1, retryDelay: 1000, staleTime: 5000 } },
  });
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="events" element={<Events />} />
        <Route path="playground" element={<Playground />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  const [client] = useState(createQueryClient);
  return (
    <QueryClientProvider client={client}>
      <LiveProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </LiveProvider>
    </QueryClientProvider>
  );
}

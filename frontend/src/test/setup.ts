import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterAll, afterEach, beforeAll } from 'vitest';

import { server } from './server';

// the first render of the lazy-loaded Overview page has to transform Recharts,
// which takes more than the 1 s default on a cold start
configure({ asyncUtilTimeout: 5000 });

// jsdom has no layout engine; Recharts' ResponsiveContainer needs this
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver = ResizeObserverStub;

// Node's fetch cannot resolve relative URLs such as "/api/stats" (a browser
// resolves them against the page). Do the same here.
const nodeFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) =>
  typeof input === 'string' && input.startsWith('/')
    ? nodeFetch(new URL(input, window.location.href).href, init)
    : nodeFetch(input, init);

// any request without a handler fails the test: no real network, ever
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());

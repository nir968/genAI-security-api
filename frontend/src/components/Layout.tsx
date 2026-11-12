import { Suspense } from 'react';
import { NavLink, Outlet } from 'react-router';

import { useHealth, useStats } from '../api/hooks';
import { useLive } from '../api/live';

const NAV = [
  { to: '/', label: 'Overview', end: true },
  { to: '/events', label: 'Events', end: false },
  { to: '/playground', label: 'Playground', end: false },
];

function GatewayStatus() {
  const health = useHealth();
  const state = health.isError ? 'offline' : health.data ? 'online' : 'checking';
  const dot = { online: 'bg-allow', offline: 'bg-block', checking: 'bg-ink-mute' }[state];
  const text = { online: 'Online', offline: 'Offline', checking: 'Checking…' }[state];
  return (
    <p className="flex items-center gap-2 text-sm text-ink-dim" aria-live="polite">
      <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-full ${dot}`} />
      <span>
        Gateway: <span className="font-medium text-ink">{text}</span>
      </span>
    </p>
  );
}

function LiveToggle() {
  const { live, setLive } = useLive();
  return (
    <button
      type="button"
      role="switch"
      aria-checked={live}
      onClick={() => setLive(!live)}
      className="btn gap-2 py-1.5"
    >
      <span
        aria-hidden="true"
        className={`h-2.5 w-2.5 rounded-full ${live ? 'animate-pulse bg-allow' : 'bg-ink-mute'}`}
      />
      {live ? 'Live' : 'Paused'}
    </button>
  );
}

/** Shown when the gateway cannot be reached or answers with errors. */
function OfflineBanner() {
  const health = useHealth();
  const stats = useStats();
  if (!health.isError && !stats.isError) return null;
  return (
    <div role="alert" className="border-b border-block/50 bg-block/15 px-4 py-2 text-center text-sm text-red-100">
      <strong className="font-semibold">API offline.</strong> The gateway is not answering
      correctly; the numbers below may be out of date.
    </div>
  );
}

export function Layout() {
  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-panel focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <header className="border-b border-line bg-panel">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
          <h1 className="text-base font-semibold tracking-tight">
            <span aria-hidden="true" className="mr-2 text-redact">
              ◆
            </span>
            GenAI Security Gateway
          </h1>
          <nav aria-label="Main" className="order-last flex w-full gap-1 sm:order-none sm:w-auto">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 text-sm font-medium ${
                    isActive ? 'bg-panel-raised text-ink' : 'text-ink-dim hover:text-ink'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <GatewayStatus />
            <LiveToggle />
          </div>
        </div>
      </header>
      <OfflineBanner />
      <main id="main" className="mx-auto max-w-7xl px-4 py-6">
        <Suspense fallback={<p className="text-sm text-ink-mute">Loading…</p>}>
          <Outlet />
        </Suspense>
      </main>
    </div>
  );
}

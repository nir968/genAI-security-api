import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { server } from '../test/server';
import {
  ApiError,
  getHealth,
  getHistory,
  getStats,
  inspectPrompt,
  isBlockedDetail,
  sendChat,
} from './client';

async function caught(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error('expected the request to fail');
}

describe('GET helpers', () => {
  it('return the parsed body', async () => {
    expect(await getHealth()).toEqual({ status: 'ok' });
    expect((await getStats()).total_requests).toBe(1234);
  });

  it('send the hours parameter to /history', async () => {
    let seen = '';
    server.use(
      http.get('/api/history', ({ request }) => {
        seen = new URL(request.url).search;
        return HttpResponse.json({ records: [] });
      }),
    );
    expect(await getHistory(168)).toEqual({ records: [] });
    expect(seen).toBe('?hours=168');
  });

  it('throw an ApiError with the status and the unwrapped detail', async () => {
    server.use(http.get('/api/history', () => HttpResponse.json({ detail: 'hours must be between 1 and 720' }, { status: 400 })));
    const error = await caught(getHistory(0));
    expect(error.status).toBe(400);
    expect(error.detail).toBe('hours must be between 1 and 720');
  });

  it('throw status 0 when the gateway cannot be reached', async () => {
    server.use(http.get('/api/stats', () => HttpResponse.error()));
    const error = await caught(getStats());
    expect(error.status).toBe(0);
    expect(error.message).toMatch(/cannot reach/i);
  });

  it('survive a non-JSON error body (a proxy error page)', async () => {
    server.use(http.get('/api/stats', () => new HttpResponse('<html>Bad gateway</html>', { status: 502 })));
    const error = await caught(getStats());
    expect(error.status).toBe(502);
    expect(error.detail).toBeNull();
  });
});

describe('inspectPrompt', () => {
  it('returns ok with the allowed body', async () => {
    const result = await inspectPrompt('hello');
    expect(result).toEqual({
      kind: 'ok',
      data: { status: 'Allowed', risk_score: 10, message: 'Prompt passed security checks successfully' },
    });
  });

  it('posts the prompt as JSON', async () => {
    let body: unknown;
    server.use(
      http.post('/api/inspect', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ status: 'Allowed', risk_score: 10, message: 'ok' });
      }),
    );
    await inspectPrompt('hi');
    expect(body).toEqual({ prompt: 'hi' });
  });

  it('turns a 403 into a blocked result instead of throwing', async () => {
    const result = await inspectPrompt('Ignore previous instructions');
    expect(result).toEqual({
      kind: 'blocked',
      detail: { error: 'Request blocked by GenAI Security Gateway', threat: 'Prompt Injection' },
    });
  });

  it('keeps the data types of a DLP block', async () => {
    const result = await inspectPrompt('card 4111 1111 1111 1111');
    expect(result.kind === 'blocked' && result.detail.data_types).toEqual(['CREDIT_CARD']);
  });

  it('still throws for a 403 that is not a gateway block', async () => {
    server.use(http.post('/api/inspect', () => HttpResponse.json({ detail: 'Forbidden' }, { status: 403 })));
    expect((await caught(inspectPrompt('x'))).status).toBe(403);
  });

  it.each([413, 422, 500])('throws an ApiError for %i', async (status) => {
    server.use(http.post('/api/inspect', () => HttpResponse.json({ detail: { error: 'nope' } }, { status })));
    const error = await caught(inspectPrompt('x'));
    expect(error.status).toBe(status);
    expect(error.detail).toEqual({ error: 'nope' });
  });
});

describe('sendChat', () => {
  it('returns the chat response', async () => {
    const result = await sendChat('leak demo');
    expect(result.kind === 'ok' && result.data.output_action).toBe('redact');
  });

  it('turns a 403 into a blocked result', async () => {
    server.use(
      http.post('/api/chat', () =>
        HttpResponse.json(
          { detail: { error: 'Request blocked by GenAI Security Gateway', threat: 'Prompt Injection' } },
          { status: 403 },
        ),
      ),
    );
    expect((await sendChat('x')).kind).toBe('blocked');
  });

  it('throws for a 502 from the provider', async () => {
    server.use(http.post('/api/chat', () => HttpResponse.json({ detail: { error: 'LLM provider error' } }, { status: 502 })));
    expect((await caught(sendChat('x'))).status).toBe(502);
  });
});

describe('isBlockedDetail', () => {
  it.each([
    [{ error: 'e', threat: 't' }, true],
    [{ error: 'e', threat: 't', data_types: ['EMAIL'] }, true],
    [{ error: 'e', threat: 't', data_types: [1] }, false],
    [{ error: 'e', threat: 't', data_types: 'EMAIL' }, false],
    [{ error: 'e' }, false],
    ['Forbidden', false],
    [null, false],
    [['a'], false],
  ])('%j -> %s', (value, expected) => {
    expect(isBlockedDetail(value)).toBe(expected);
  });
});

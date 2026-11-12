import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { STATS, sampleHistory } from './fixtures';

const CARD = '4111 1111 1111 1111';
const IBAN = 'IL620108000000099999999';

/**
 * A tiny stand-in for the gateway. It answers with the same JSON shapes as
 * gateway/main.py, using a few trigger words instead of the real DLP engine.
 */
export const handlers = [
  http.get('/api/health', () => HttpResponse.json({ status: 'ok' })),
  http.get('/api/stats', () => HttpResponse.json(STATS)),
  http.get('/api/history', () => HttpResponse.json({ records: sampleHistory() })),

  http.post('/api/inspect', async ({ request }) => {
    const { prompt } = (await request.json()) as { prompt: string };
    if (/ignore previous instructions/i.test(prompt)) {
      return HttpResponse.json(
        { detail: { error: 'Request blocked by GenAI Security Gateway', threat: 'Prompt Injection' } },
        { status: 403 },
      );
    }
    if (prompt.includes(CARD)) {
      return HttpResponse.json(
        {
          detail: {
            error: 'Request blocked by GenAI Security Gateway',
            threat: 'DLP Violation',
            data_types: ['CREDIT_CARD'],
          },
        },
        { status: 403 },
      );
    }
    if (prompt.includes(IBAN)) {
      return HttpResponse.json({
        status: 'Redacted',
        risk_score: 60,
        redacted_prompt: prompt.replace(IBAN, '[REDACTED:IBAN]'),
        data_types: ['IBAN'],
      });
    }
    if (prompt.includes('dana@example.com')) {
      return HttpResponse.json({
        status: 'Allowed',
        risk_score: 30,
        message: 'Prompt passed security checks successfully',
        alerts: ['EMAIL'],
      });
    }
    return HttpResponse.json({
      status: 'Allowed',
      risk_score: 10,
      message: 'Prompt passed security checks successfully',
    });
  }),

  http.post('/api/chat', async ({ request }) => {
    const { message } = (await request.json()) as { message: string };
    if (/leak demo/i.test(message)) {
      return HttpResponse.json({
        response: 'Sample card ****1111 and key [REDACTED:AWS_ACCESS_KEY]',
        input_action: 'allow',
        output_action: 'redact',
        data_types: { input: [], output: ['AWS_ACCESS_KEY', 'CREDIT_CARD'] },
      });
    }
    return HttpResponse.json({
      response: `[mock] You said: ${message}`,
      input_action: 'allow',
      output_action: 'allow',
      data_types: { input: [], output: [] },
    });
  }),
];

export const server = setupServer(...handlers);

import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/client';
import { describeApiError } from './errors';

describe('describeApiError', () => {
  it('explains a network failure', () => {
    expect(describeApiError(new ApiError(0, null))).toMatch(/cannot reach the gateway/i);
  });

  it('names the limit for a 413', () => {
    const message = describeApiError(new ApiError(413, { error: 'Input too long', max_chars: 20000 }));
    expect(message).toContain('20,000');
  });

  it('copes with a 413 without details', () => {
    expect(describeApiError(new ApiError(413, null))).toMatch(/too long/i);
    expect(describeApiError(new ApiError(413, { max_chars: 'many' }))).toMatch(/too long/i);
  });

  it('explains a 422', () => {
    expect(describeApiError(new ApiError(422, [{ msg: 'field required' }]))).toMatch(/invalid/i);
  });

  it('explains a 502 from the model provider', () => {
    expect(describeApiError(new ApiError(502, { error: 'LLM provider error' }))).toMatch(/language model/i);
  });

  it('reports other server errors with the status', () => {
    expect(describeApiError(new ApiError(500, null))).toContain('500');
  });

  it('reports other client errors with the status', () => {
    expect(describeApiError(new ApiError(400, 'hours must be between 1 and 720'))).toContain('400');
  });

  it('has a generic message for anything else', () => {
    expect(describeApiError(new Error('boom'))).toMatch(/something went wrong/i);
    expect(describeApiError('text')).toMatch(/something went wrong/i);
  });
});

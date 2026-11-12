import { ApiError } from '../api/client';

function maxChars(detail: unknown): number | null {
  if (typeof detail === 'object' && detail !== null && 'max_chars' in detail) {
    const value = (detail as { max_chars: unknown }).max_chars;
    if (typeof value === 'number') return value;
  }
  return null;
}

/** A message for the user for any error raised while calling the gateway. */
export function describeApiError(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'Something went wrong. Please try again.';
  }
  switch (error.status) {
    case 0:
      return 'Cannot reach the gateway. Check that it is running and try again.';
    case 413: {
      const limit = maxChars(error.detail);
      return limit === null
        ? 'The input is too long for the gateway.'
        : `The input is too long: the gateway accepts at most ${limit.toLocaleString('en-US')} characters.`;
    }
    case 422:
      return 'The gateway rejected the request as invalid. Check the text and try again.';
    case 502:
      return 'The language model provider failed to answer. Try again in a moment.';
    default:
      return error.status >= 500
        ? `The gateway returned an error (HTTP ${error.status}). Try again in a moment.`
        : `The request was rejected (HTTP ${error.status}).`;
  }
}

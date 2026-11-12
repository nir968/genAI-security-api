import { describe, expect, it } from 'vitest';

import { makeRecord } from '../test/fixtures';
import { collectDataTypes, countDataTypes } from './dataTypes';

describe('countDataTypes', () => {
  it('returns nothing for no records or records without findings', () => {
    expect(countDataTypes([])).toEqual([]);
    expect(countDataTypes([makeRecord()])).toEqual([]);
  });

  it('counts records per type, highest first, ties by name', () => {
    const records = [
      makeRecord({ data_types: ['IBAN'] }),
      makeRecord({ data_types: ['CREDIT_CARD', 'EMAIL'] }),
      makeRecord({ data_types: ['CREDIT_CARD'] }),
      makeRecord({ data_types: ['EMAIL'] }),
      makeRecord({ data_types: ['CREDIT_CARD'] }),
    ];
    expect(countDataTypes(records)).toEqual([
      { dataType: 'CREDIT_CARD', count: 3 },
      { dataType: 'EMAIL', count: 2 },
      { dataType: 'IBAN', count: 1 },
    ]);
  });

  it('counts a type once per record even if it is listed twice', () => {
    expect(countDataTypes([makeRecord({ data_types: ['EMAIL', 'EMAIL'] })])).toEqual([
      { dataType: 'EMAIL', count: 1 },
    ]);
  });
});

describe('collectDataTypes', () => {
  it('lists each distinct type once, sorted', () => {
    const records = [
      makeRecord({ data_types: ['IBAN', 'EMAIL'] }),
      makeRecord({ data_types: ['EMAIL'] }),
      makeRecord(),
    ];
    expect(collectDataTypes(records)).toEqual(['EMAIL', 'IBAN']);
  });
});

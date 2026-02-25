import { describe, expect, it } from 'vitest'
import * as utils from '../../src/utils'
import * as typesBarrel from '../../src/types'
import type { BatchDeleteEntry, BatchSetEntry, StorageManagerOptions } from '../../src/session/storage/types'
import type { SerializedSessionRecord } from '../../src/session/record/types'
import type { PreKeyBundle } from '../../src/session/builder/types'
import type { SignalLogger } from '../../src/observability'

describe('barrel and type modules', () => {
  it('exports utils runtime symbols', () => {
    expect(utils.assertUint8).toBeTypeOf('function')
    expect(utils.enqueue).toBeTypeOf('function')
    expect(utils.secureZero).toBeTypeOf('function')
    expect(typesBarrel).toBeDefined()
  })

  it('keeps strict type-safety contracts compilable', () => {
    const setEntry: BatchSetEntry<number> = { key: 'x', value: 1 }
    const delEntry: BatchDeleteEntry = { key: 'x' }
    const recordShape: SerializedSessionRecord = { _sessions: {}, version: '1' }
    const storageOpts: StorageManagerOptions<number> = {
      adapter: {
        get: () => 1,
        set: () => undefined,
        delete: () => undefined,
      },
    }
    const logger: SignalLogger = {
      debug: () => undefined,
      warn: () => undefined,
    }
    const bundle: PreKeyBundle = {
      identityKey: new Uint8Array([1]),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array([1]), signature: new Uint8Array([1]) },
    }

    expect(setEntry.value).toBe(1)
    expect(delEntry.key).toBe('x')
    expect(recordShape.version).toBe('1')
    expect(storageOpts.adapter.get('k')).toBe(1)
    expect(bundle.registrationId).toBe(1)
    logger.debug('queue-size', { size: '1' })
  })
})

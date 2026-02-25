import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { AtomicJsonFileAsyncStorageAdapter } from '../../src/session/storage/atomic-json-file'

describe('AtomicJsonFileAsyncStorageAdapter', () => {
  it('persists, loads, batches and secure clears data', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'swt-store-'))
    const file = join(dir, 'db.json')

    const adapter = new AtomicJsonFileAsyncStorageAdapter(file, { flushEveryWrites: 1, fsyncOnFlush: true })
    await adapter.set('a', new Uint8Array([1, 2]))
    await adapter.setMany([{ key: 'b', value: new Uint8Array([3]) }])

    expect(Array.from((await adapter.get('a')) ?? [])).toEqual([1, 2])
    expect((await adapter.getMany(['a', 'b', 'x']))[2]).toBeUndefined()

    await adapter.zeroize('a')
    expect(Array.from((await adapter.get('a')) ?? [])).toEqual([0, 0])

    await adapter.deleteMany([{ key: 'b' }])
    expect(await adapter.get('b')).toBeUndefined()

    await adapter.clear({ secure: true })
    await adapter.close()

    const reopened = new AtomicJsonFileAsyncStorageAdapter(file, { flushEveryWrites: 1 })
    expect(await reopened.get('a')).toBeUndefined()
  })
})

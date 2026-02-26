import { describe, expect, it, vi } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { SqliteAsyncStorageAdapter } from '../../src/session/storage/sqlite-async'
import { createSessionStorage } from '../../src/session/storage/adapter'
import { SessionRecord } from '../../src/session/record'

async function hasNodeSqliteSupport(): Promise<boolean> {
  try {
    await import('node:sqlite' as string)
    return true
  } catch {
    return false
  }
}

const sqliteSupported = await hasNodeSqliteSupport()
const describeSqlite = sqliteSupported ? describe : describe.skip

describeSqlite('SqliteAsyncStorageAdapter', () => {
  it('stores and loads complex values with Uint8Array payloads', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'swt-sqlite-'))
    const file = join(dir, 'store.db')

    const adapter = await SqliteAsyncStorageAdapter.open<unknown>(file, {
      walMode: 'WAL',
      synchronous: 'FULL',
      secureDelete: false,
    })

    const complex = {
      n: 42,
      nested: {
        pubKey: new Uint8Array([1, 2, 3]),
        privKey: new Uint8Array([4, 5, 6]),
      }
    }

    await adapter.set('complex', complex)
    const loaded = await adapter.get('complex') as typeof complex

    expect(loaded.n).toBe(42)
    expect(Array.from(loaded.nested.pubKey)).toEqual([1, 2, 3])
    expect(Array.from(loaded.nested.privKey)).toEqual([4, 5, 6])

    await adapter.setMany([
      { key: 'batch:1', value: { a: 1 } },
      { key: 'batch:2', value: { a: 2 } },
    ])
    const batch = await adapter.getMany(['batch:1', 'batch:2'])
    expect(batch[0]).toEqual({ a: 1 })
    expect(batch[1]).toEqual({ a: 2 })

    await adapter.deleteMany([{ key: 'batch:1' }, { key: 'batch:2' }])
    const deleted = await adapter.getMany(['batch:1', 'batch:2'])
    expect(deleted[0]).toBeUndefined()
    expect(deleted[1]).toBeUndefined()

    await adapter.clear()
    await adapter.close()

    const customCodecAdapter = await SqliteAsyncStorageAdapter.open<number>(join(dir, 'codec.db'), {
      codec: {
        encode: (value) => Uint8Array.from([value]),
        decode: (bytes) => bytes[0] ?? 0,
      }
    })
    await customCodecAdapter.set('u8', 77)
    expect(await customCodecAdapter.get('u8')).toBe(77)
    await customCodecAdapter.close()
  })

  it('enforces transactional rollback and atomic session+prekey operation', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'swt-sqlite-'))
    const file = join(dir, 'tx.db')

    const adapter = await SqliteAsyncStorageAdapter.open<unknown>(file)

    await expect(adapter.transaction(async () => {
      await adapter.set('tx:key', { value: 1 })
      throw new Error('rollback')
    })).rejects.toThrow('rollback')

    expect(await adapter.get('tx:key')).toBeUndefined()

    await adapter.transaction(async () => {
      await adapter.set('nested:root', { ok: true })
      await adapter.transaction(async () => {
        await adapter.set('nested:child', { ok: true })
      })
    })

    await expect(adapter.transaction(async () => {
      await adapter.transaction(async () => {
        throw new Error('nested-rollback')
      })
    })).rejects.toThrow('nested-rollback')

    const store = createSessionStorage(adapter, {
      requireAtomicSessionAndPreKey: true
    })

    await adapter.set('prekey:77', {
      pubKey: new Uint8Array([9]),
      privKey: new Uint8Array([8]),
    })
    await store.storeSession('peer.1', new SessionRecord())
    await store.storeSessionAndRemovePreKey('peer.1', new SessionRecord(), 77)

    expect(await adapter.get('prekey:77')).toBeUndefined()

    await adapter.close()
  })

  it('zeroizes sensitive entries and securely clears persisted rows', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'swt-sqlite-'))
    const file = join(dir, 'secure.db')

    const adapter = await SqliteAsyncStorageAdapter.open<unknown>(file)
    await adapter.set('secret', {
      key: new Uint8Array([7, 7, 7, 7]),
      parts: [new Uint8Array([1, 2])],
      label: 'token'
    })

    await adapter.zeroize('secret')
    const zeroized = await adapter.get('secret') as { key: Uint8Array; parts: Uint8Array[]; label: string } | undefined
    expect(zeroized?.label).toBe('token')
    expect(Array.from(zeroized?.key ?? [])).toEqual([0, 0, 0, 0])
    expect(Array.from(zeroized?.parts?.[0] ?? [])).toEqual([0, 0])

    await adapter.clear({ secure: true })
    expect(await adapter.get('secret')).toBeUndefined()

    const anyAdapter = adapter as unknown as {
      getStmt: { get: (key: string) => unknown }
      zeroizeStmt: { run: (key: string) => void }
      codec: { encode: (value: unknown) => Uint8Array; decode: (value: Uint8Array) => unknown }
      listKeysStmt: { all?: () => unknown[] }
      zeroize: (key: string) => Promise<void>
      clear: (options?: { secure?: boolean }) => Promise<void>
      get: (key: string) => Promise<unknown>
    }

    const originalGet = anyAdapter.getStmt.get
    const originalCodec = anyAdapter.codec
    const originalZeroizeRun = anyAdapter.zeroizeStmt.run
    const originalListKeys = anyAdapter.listKeysStmt

    anyAdapter.getStmt = { get: () => undefined }
    await anyAdapter.zeroize('missing')

    anyAdapter.getStmt = { get: () => ({ value: 'not-bytes' }) }
    await anyAdapter.zeroize('invalid')

    const zeroizeRun = vi.fn()
    anyAdapter.zeroizeStmt = { run: zeroizeRun }
    anyAdapter.getStmt = { get: () => ({ value: new Uint8Array([1, 2, 3]) }) }
    anyAdapter.codec = {
      encode: originalCodec.encode,
      decode: () => { throw new Error('decode-failed') }
    }
    await anyAdapter.zeroize('fallback')
    expect(zeroizeRun).toHaveBeenCalledWith('fallback')

    anyAdapter.getStmt = { get: () => ({ nope: true }) }
    expect(await anyAdapter.get('missing-value')).toBeUndefined()

    anyAdapter.listKeysStmt = {}
    await anyAdapter.clear({ secure: true })

    anyAdapter.listKeysStmt = {
      all: () => [{ key: 123 }, { key: 'secret' }]
    }
    await anyAdapter.clear({ secure: true })

    anyAdapter.getStmt = { get: originalGet }
    anyAdapter.codec = originalCodec
    anyAdapter.zeroizeStmt = { run: originalZeroizeRun }
    anyAdapter.listKeysStmt = originalListKeys

    await adapter.close()
  })
})

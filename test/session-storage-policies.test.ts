import { describe, expect, it, vi } from 'vitest'
import { createSessionStorage } from '../src/session/storage/adapter'
import { InMemoryStorage } from '../src/session/storage/in-memory'
import { SessionRecord } from '../src/session/record'

describe('session storage identity policy', () => {
  it('supports explicit first-use identity approval callback', async () => {
    const adapter = new InMemoryStorage<unknown>()
    const onFirstUseIdentity = vi.fn<(_addressName: string, _identityKey: Uint8Array) => Promise<boolean>>()
    onFirstUseIdentity.mockResolvedValueOnce(false).mockResolvedValueOnce(true)

    const store = createSessionStorage(adapter, {
      trustOnFirstUse: true,
      onFirstUseIdentity,
    })

    const key = new Uint8Array([1, 2, 3])
    await expect(store.isTrustedIdentity('alice', key)).resolves.toBe(false)
    await expect(store.isTrustedIdentity('alice', key)).resolves.toBe(true)
    await expect(store.isTrustedIdentity('alice', key)).resolves.toBe(true)
    expect(onFirstUseIdentity).toHaveBeenCalledTimes(2)
  })

  it('can replace identity only when mismatch callback approves', async () => {
    const adapter = new InMemoryStorage<unknown>()
    const onIdentityMismatch = vi.fn()
      .mockResolvedValueOnce('replace')
      .mockResolvedValueOnce('reject')
    const store = createSessionStorage(adapter, { onIdentityMismatch })

    const first = new Uint8Array([7, 7, 7])
    const rotated = new Uint8Array([8, 8, 8])

    await expect(store.isTrustedIdentity('bob', first)).resolves.toBe(true)
    await expect(store.isTrustedIdentity('bob', rotated)).resolves.toBe(true)
    await expect(store.isTrustedIdentity('bob', first)).resolves.toBe(false)
    expect(onIdentityMismatch).toHaveBeenCalledTimes(2)
  })
})

describe('session storage atomic prekey policy', () => {
  it('rejects non-transactional adapter when strict atomic mode is enabled', async () => {
    const adapter = new InMemoryStorage<unknown>()
    const store = createSessionStorage(adapter, { requireAtomicSessionAndPreKey: true })

    await expect(
      store.storeSessionAndRemovePreKey('peer.1', new SessionRecord(), 33),
    ).rejects.toThrow('Atomic session+prekey operation requires adapter.transaction() support')
  })

  it('uses adapter transaction when strict atomic mode is enabled', async () => {
    const base = new InMemoryStorage<unknown>()
    const txAdapter = {
      get: (key: string) => base.get(key),
      set: (key: string, value: unknown) => base.set(key, value),
      delete: (key: string) => base.delete(key),
      transaction: async <T>(run: (tx: { get(key: string): unknown; set(key: string, value: unknown): void; delete(key: string): void }) => Promise<T> | T): Promise<T> => {
        const tx = {
          get: (key: string) => base.get(key),
          set: (key: string, value: unknown) => base.set(key, value),
          delete: (key: string) => base.delete(key),
        }
        return await run(tx)
      },
    }

    const store = createSessionStorage(txAdapter, { requireAtomicSessionAndPreKey: true })
    await expect(store.storeSessionAndRemovePreKey('peer.1', new SessionRecord(), 33)).resolves.toBeUndefined()
  })
})

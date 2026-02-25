import { describe, expect, it, vi } from 'vitest'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { decryptAsync, encryptAsync, establishSessionAsync } from '../../src/public/async'

describe('public async helpers', () => {
  it('delegates establishSessionAsync to SessionBuilder.initOutgoing', async () => {
    const spy = vi.spyOn(SessionBuilder.prototype, 'initOutgoing').mockResolvedValueOnce(undefined)

    const storage = {
      isTrustedIdentity: async () => true,
      loadSession: async () => undefined,
      storeSession: async () => undefined,
      getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(32) }),
      loadPreKey: async () => undefined,
      loadSignedPreKey: async () => undefined,
    }

    await establishSessionAsync(storage, new ProtocolAddress('x', 1), {
      identityKey: new Uint8Array(32),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32), signature: new Uint8Array(64) },
    })

    expect(spy).toHaveBeenCalledOnce()
    spy.mockRestore()
  })

  it('delegates encryptAsync/decryptAsync wrappers', async () => {
    const fakeCipher = {
      encrypt: vi.fn(async () => ({ type: 1, body: new Uint8Array([1]), registrationId: 1 })),
      decryptWhisperMessage: vi.fn(async () => new Uint8Array([2])),
    }

    const encrypted = await encryptAsync(fakeCipher as never, new Uint8Array([9]))
    const decrypted = await decryptAsync(fakeCipher as never, new Uint8Array([8]))

    expect(encrypted.type).toBe(1)
    expect(Array.from(decrypted)).toEqual([2])
  })
})

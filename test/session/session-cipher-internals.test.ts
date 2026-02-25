import { describe, expect, it, vi } from 'vitest'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionEntry } from '../../src/session/record'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { crypto } from '../../src/crypto'
import { initCrypto } from '../../src/curve'

function makeSessionEntry(): SessionEntry {
  const entry = new SessionEntry()
  entry.registrationId = 1
  entry.currentRatchet = {
    ephemeralKeyPair: { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
    lastRemoteEphemeralKey: new Uint8Array(32).fill(3),
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(4),
  }
  entry.indexInfo = {
    baseKey: new Uint8Array(32).fill(5),
    baseKeyType: BaseKeyType.OURS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: new Uint8Array(32).fill(6),
  }
  return entry
}

describe('SessionCipher internal guards', () => {
  const storage = {
    loadSession: async () => undefined,
    storeSession: async () => undefined,
    getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(32) }),
    isTrustedIdentity: async () => true,
    getOurRegistrationId: async () => 1,
    loadPreKey: async () => undefined,
    loadSignedPreKey: async () => undefined,
    removePreKey: async () => undefined,
  }

  it('covers deriveSecrets and verifyMAC error branches', () => {
    const cipher = new SessionCipher(storage, new ProtocolAddress('p', 1))
    const hkdfSpy = vi.spyOn(crypto, 'hkdf').mockReturnValueOnce(new Uint8Array(16))

    expect(() => (cipher as unknown as { deriveSecrets: Function }).deriveSecrets(new Uint8Array([1]), new Uint8Array(32), new Uint8Array([1]), 1))
      .toThrow('HKDF derivation failed: expected 32 bytes, got 16')

    hkdfSpy.mockRestore()

    expect(() => (cipher as unknown as { verifyMAC: Function }).verifyMAC(new Uint8Array([1]), new Uint8Array(32), new Uint8Array([1]), 8))
      .toThrow('MAC too short')
  })

  it('covers fillMessageKeys and maybeStepRatchet branches', async () => {
    await initCrypto()
    const cipher = new SessionCipher(storage, new ProtocolAddress('p', 1))
    const entry = makeSessionEntry()

    const chain = {
      chainKey: { counter: 0, key: undefined as Uint8Array | undefined },
      chainType: ChainType.SENDING,
      messageKeys: new Map<number, Uint8Array>(),
    }

    expect(() => (cipher as unknown as { fillMessageKeys: Function }).fillMessageKeys(chain, 1)).toThrow('Chain closed')

    chain.chainKey.key = new Uint8Array(32)
    expect(() => (cipher as unknown as { fillMessageKeys: Function }).fillMessageKeys(chain, 3001)).toThrow('Over 2000 messages into the future')

    chain.chainKey.counter = Number.MAX_SAFE_INTEGER - 10
    expect(() => (cipher as unknown as { fillMessageKeys: Function }).fillMessageKeys(chain, Number.MAX_SAFE_INTEGER)).toThrow('Counter would overflow')

    entry.addChain(entry.currentRatchet.lastRemoteEphemeralKey, {
      chainKey: { counter: 0, key: new Uint8Array(32).fill(1) },
      chainType: ChainType.RECEIVING,
      messageKeys: new Map(),
    })

    entry.addChain(entry.currentRatchet.ephemeralKeyPair.pubKey, {
      chainKey: { counter: 3, key: new Uint8Array(32).fill(1) },
      chainType: ChainType.SENDING,
      messageKeys: new Map(),
    })

    await (cipher as unknown as { maybeStepRatchet: Function }).maybeStepRatchet(entry, new Uint8Array(32).fill(9), 1)
    expect(entry.currentRatchet.lastRemoteEphemeralKey).toEqual(new Uint8Array(32).fill(9))
    expect(entry.currentRatchet.previousCounter).toBe(3)
  })
})

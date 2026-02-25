import { describe, expect, it } from 'vitest'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionError } from '../../src/signal-errors'
import { SessionEntry } from '../../src/session/record'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'

describe('SessionCipher guard errors', () => {
  const storage = {
    loadSession: async () => undefined,
    storeSession: async () => undefined,
    getOurIdentity: async () => ({ pubKey: new Uint8Array(32).fill(7), privKey: new Uint8Array(32) }),
    isTrustedIdentity: async () => true,
    getOurRegistrationId: async () => 1,
    loadPreKey: async () => undefined,
    loadSignedPreKey: async () => undefined,
    removePreKey: async () => undefined,
  }

  it('throws on missing sessions and invalid prekey envelopes', async () => {
    const cipher = new SessionCipher(storage, new ProtocolAddress('peer', 1))
    await expect(cipher.decryptWhisperMessage(new Uint8Array([0]))).rejects.toBeInstanceOf(SessionError)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array())).rejects.toThrow('Invalid PreKeyWhisperMessage')
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x00, 0x01]))).rejects.toThrow('Invalid PreKeyWhisperMessage')
  })

  it('does not mutate session state on MAC failure (transactional decrypt)', async () => {
    const cipher = new SessionCipher(storage, new ProtocolAddress('peer', 1))
    const session = new SessionEntry()
    session.registrationId = 1
    const remoteEphemeral = new Uint8Array(32).fill(2)

    session.currentRatchet = {
      ephemeralKeyPair: { pubKey: new Uint8Array(32).fill(3), privKey: new Uint8Array(32).fill(4) },
      lastRemoteEphemeralKey: remoteEphemeral,
      previousCounter: 0,
      rootKey: new Uint8Array(32).fill(5),
    }

    session.indexInfo = {
      baseKey: new Uint8Array(32).fill(9),
      baseKeyType: BaseKeyType.THEIRS,
      closed: -1,
      used: Date.now(),
      created: Date.now(),
      remoteIdentityKey: new Uint8Array(32).fill(6),
    }

    const chain = {
      chainKey: { counter: 1, key: new Uint8Array(32).fill(1) },
      chainType: ChainType.RECEIVING,
      messageKeys: new Map<number, Uint8Array>([[1, new Uint8Array(32).fill(8)]]),
    }
    session.addChain(remoteEphemeral, chain)

    const whisper = WhisperMessageEncoder.encodeWhisperMessage({
      ephemeralKey: remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      ciphertext: new Uint8Array(28).fill(9),
    })
    const body = new Uint8Array(1 + whisper.length + 8)
    body[0] = 0x33
    body.set(whisper, 1)
    body.set(new Uint8Array(8).fill(0xaa), 1 + whisper.length)

    await expect((cipher as unknown as { doDecryptWhisperMessage: Function }).doDecryptWhisperMessage(body, session))
      .rejects.toThrow('MAC verification failed')

    const originalChain = session.getChain(remoteEphemeral)
    expect(originalChain?.messageKeys.has(1)).toBe(true)
    expect(originalChain?.chainKey.counter).toBe(1)
  })
})
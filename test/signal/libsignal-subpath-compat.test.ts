import { describe, expect, it } from 'vitest'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import * as compatCrypto from '../../src/compat/libsignal/src/crypto'
import * as compatCurve from '../../src/compat/libsignal/src/curve'
import { PreKeyWhisperMessage, WhisperMessage } from '../../src/compat/libsignal/src/protobufs'

describe('libsignal subpath compatibility shims', () => {
  it('supports crypto helpers used by baileys signal group implementation', () => {
    const key = Buffer.alloc(32, 1)
    const iv = Buffer.alloc(16, 2)
    const payload = Buffer.from('compat-group-payload', 'utf8')

    const encrypted = compatCrypto.encrypt(key, payload, iv)
    const decrypted = compatCrypto.decrypt(key, encrypted, iv)
    expect(Buffer.from(decrypted).toString('utf8')).toBe('compat-group-payload')

    const mac = compatCrypto.calculateMAC(key, Buffer.from('a'))
    compatCrypto.verifyMAC(Buffer.from('a'), key, mac.subarray(0, 8), 8)

    const derived = compatCrypto.deriveSecrets(Buffer.alloc(32, 3), Buffer.alloc(32, 4), Buffer.from('WhisperGroup'))
    expect(derived).toHaveLength(3)
    expect(derived[0]).toBeInstanceOf(Buffer)
  })

  it('supports curve helpers used by baileys signal group implementation', () => {
    const alice = compatCurve.generateKeyPair()
    const bob = compatCurve.generateKeyPair()

    const aShared = compatCurve.calculateAgreement(bob.pubKey, alice.privKey)
    const bShared = compatCurve.calculateAgreement(alice.pubKey, bob.privKey)
    expect(aShared.equals(bShared)).toBe(true)

    const signature = compatCurve.calculateSignature(alice.privKey, bob.pubKey)
    expect(compatCurve.verifySignature(alice.pubKey, bob.pubKey, signature)).toBe(true)
  })

  it('supports protobuf decode/encode helpers from libsignal/src/protobufs', () => {
    const whisper = WhisperMessage.encode({
      ephemeralKey: new Uint8Array(32).fill(9),
      counter: 7,
      previousCounter: 6,
      ciphertext: new Uint8Array([1, 2, 3, 4])
    }).finish()

    const whisperDecoded = WhisperMessage.decode(whisper)
    expect(whisperDecoded.counter).toBe(7)
    expect(whisperDecoded.previousCounter).toBe(6)

    const preKeyBytes = WhisperMessageEncoder.encodePreKeyWhisperMessage({
      identityKey: new Uint8Array(33).fill(5),
      registrationId: 42,
      baseKey: new Uint8Array(33).fill(7),
      signedPreKeyId: 10,
      preKeyId: 11,
      message: new Uint8Array([8, 9, 10]),
    })

    const decoded = PreKeyWhisperMessage.decode(preKeyBytes)
    expect(decoded.registrationId).toBe(42)
    expect(decoded.signedPreKeyId).toBe(10)
    expect(decoded.preKeyId).toBe(11)
  })
})


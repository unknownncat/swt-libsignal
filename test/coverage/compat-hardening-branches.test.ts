import { describe, expect, it, vi } from 'vitest'
import * as compatCrypto from '../../src/compat/libsignal/src/crypto'
import * as compatCurve from '../../src/compat/libsignal/src/curve'
import * as compatKeyhelper from '../../src/compat/libsignal/src/keyhelper'
import { PreKeyWhisperMessage } from '../../src/compat/libsignal/src/protobufs'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { LegacyLibsignalSuite } from '../../src/session/cipher/crypto-suite'
import { ProtocolAddress } from '../../src/protocol_address'
import { signalCrypto } from '../../src/curve'

const builderStorage = {
  isTrustedIdentity: async () => true,
  loadSession: async () => undefined,
  storeSession: async () => undefined,
  getOurIdentity: async () => ({
    pubKey: new Uint8Array(33).fill(5),
    privKey: new Uint8Array(32).fill(2),
  }),
  loadPreKey: async () => undefined,
  loadSignedPreKey: async () => undefined,
}

const cipherStorage = {
  loadSession: async () => undefined,
  storeSession: async () => undefined,
  getOurIdentity: async () => ({ pubKey: new Uint8Array(33).fill(5), privKey: new Uint8Array(32).fill(2) }),
  isTrustedIdentity: async () => true,
  getOurRegistrationId: async () => 1,
  loadPreKey: async () => undefined,
  loadSignedPreKey: async () => undefined,
  removePreKey: async () => undefined,
}

describe('compat hardening branch coverage', () => {
  it('covers libsignal compat crypto guard/error branches', () => {
    const key = Buffer.alloc(32, 1)
    const iv = Buffer.alloc(16, 2)

    expect(() => compatCrypto.encrypt('x' as never, Buffer.alloc(1), iv)).toThrow('Expected Buffer')
    expect(() => compatCrypto.encrypt(Object.create(null) as never, Buffer.alloc(1), iv)).toThrow('got: object')
    expect(() => compatCrypto.hash('x' as never)).toThrow('Expected Buffer')
    expect(() => compatCrypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(16), Buffer.from('i'))).toThrow('incorrect length')
    expect(() => compatCrypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('i'), 0)).toThrow('between 1 and 3')
    expect(compatCrypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('i'), 3)).toHaveLength(3)
    expect(compatCrypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('i'), 2)).toHaveLength(2)
    expect(compatCrypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('i'), 1)).toHaveLength(1)

    const mac = compatCrypto.calculateMAC(key, Buffer.from('payload'))
    expect(() => compatCrypto.verifyMAC(Buffer.from('payload'), key, mac.subarray(0, 4), 8)).toThrow('Bad MAC length')
    expect(() => compatCrypto.verifyMAC(Buffer.from('payload'), key, Buffer.alloc(8), 8)).toThrow('Bad MAC')
  })

  it('covers libsignal compat curve/keyhelper guard branches', () => {
    const keyPair = compatCurve.generateKeyPair()
    const other = compatCurve.generateKeyPair()

    expect(() => compatCurve.getPublicFromPrivateKey(undefined as never)).toThrow('Undefined private key')
    expect(() => compatCurve.getPublicFromPrivateKey(new Uint8Array(32) as never)).toThrow('Invalid private key type')
    expect(() => compatCurve.getPublicFromPrivateKey(Object.create(null) as never)).toThrow('Invalid private key type: object')
    expect(compatCurve.getPublicFromPrivateKey(keyPair.privKey).length).toBe(33)
    expect(() => compatCurve.calculateAgreement(other.pubKey, Buffer.alloc(16))).toThrow('Incorrect private key length')
    expect(() => compatCurve.calculateAgreement('bad' as never, keyPair.privKey)).toThrow('Invalid public key type')
    expect(() => compatCurve.calculateAgreement(Object.create(null) as never, keyPair.privKey)).toThrow('Invalid public key type: object')
    expect(() => compatCurve.calculateAgreement(Buffer.alloc(33), keyPair.privKey)).toThrow('Invalid public key')
    expect(() => compatCurve.calculateSignature(keyPair.privKey, undefined as never)).toThrow('Invalid message')
    expect(() => compatCurve.verifySignature(other.pubKey, undefined as never, new Uint8Array(64))).toThrow('Invalid message')
    expect(() => compatCurve.verifySignature(other.pubKey, Buffer.from('msg'), new Uint8Array(63))).toThrow('Invalid signature')
    expect(compatCurve.verifySignature(Buffer.alloc(32), Buffer.from('msg'), new Uint8Array(64), true)).toBe(true)
    expect(compatCurve.verifySignature(other.pubKey, Buffer.from('msg'), new Uint8Array(64), true)).toBe(true)

    expect(() => compatKeyhelper.generateSignedPreKey({ pubKey: Buffer.alloc(33), privKey: Buffer.alloc(31) }, 1)).toThrow('Invalid argument for identityKeyPair')
    expect(() => compatKeyhelper.generateSignedPreKey(keyPair, -1)).toThrow('Invalid argument for signedKeyId')
    expect(() => compatKeyhelper.generatePreKey(-1)).toThrow('Invalid argument for keyId')

    const signed = compatKeyhelper.generateSignedPreKey(keyPair, 4)
    expect(signed.keyId).toBe(4)
    expect(signed.signature.length).toBe(64)
    expect(compatKeyhelper.generateIdentityKeyPair().pubKey.length).toBe(33)
    expect(compatKeyhelper.generateRegistrationId()).toBeGreaterThanOrEqual(0)
    expect(compatKeyhelper.generatePreKey(8).keyId).toBe(8)
  })

  it('covers protobuf encode helper and builder private compatibility branches', async () => {
    const preKeyPayload = PreKeyWhisperMessage.encode({
      identityKey: new Uint8Array(33).fill(1),
      registrationId: 5,
      baseKey: new Uint8Array(33).fill(2),
      signedPreKeyId: 7,
      preKeyId: 8,
      message: new Uint8Array([1, 2, 3]),
    }).finish()
    expect(preKeyPayload.length).toBeGreaterThan(0)

    const strictBuilder = new SessionBuilder(builderStorage, new ProtocolAddress('peer', 1), { compatMode: 'strict' })
    const legacyBuilder = new SessionBuilder(builderStorage, new ProtocolAddress('peer', 1), { compatMode: 'legacy' })

    const strictPair = await (strictBuilder as never as {
      generateSessionDhKeyPair: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>
    }).generateSessionDhKeyPair()
    expect(strictPair.publicKey.length).toBe(32)

    const legacyPair = await (legacyBuilder as never as {
      generateSessionDhKeyPair: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>
    }).generateSessionDhKeyPair()
    expect(legacyPair.publicKey.length).toBe(33)

    expect((strictBuilder as never as {
      verifyLegacyCurveSignature: (identityKey: Uint8Array, signedPreKeyPublicKey: Uint8Array, signature: Uint8Array) => boolean
    }).verifyLegacyCurveSignature(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array(64))).toBe(false)

    expect((legacyBuilder as never as {
      verifySignedPreKeySignature: (identityKey: Uint8Array, signedPreKeyPublicKey: Uint8Array, signature: Uint8Array) => boolean
    }).verifySignedPreKeySignature(new Uint8Array(31), new Uint8Array(33).fill(5), new Uint8Array(64))).toBe(false)

    expect((strictBuilder as never as {
      verifySignedPreKeySignature: (identityKey: Uint8Array, signedPreKeyPublicKey: Uint8Array, signature: Uint8Array) => boolean
    }).verifySignedPreKeySignature(new Uint8Array(32), new Uint8Array(32), new Uint8Array(63))).toBe(false)

    const verifySpy = vi.spyOn(signalCrypto, 'verify').mockImplementation(() => {
      throw new Error('verify failure')
    })
    try {
      expect((strictBuilder as never as {
        verifySignedPreKeySignature: (identityKey: Uint8Array, signedPreKeyPublicKey: Uint8Array, signature: Uint8Array) => boolean
      }).verifySignedPreKeySignature(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(64))).toBe(false)
    } finally {
      verifySpy.mockRestore()
    }

    expect(() => (strictBuilder as never as {
      normalizeCurvePublicKey: (publicKey: Uint8Array) => Uint8Array
    }).normalizeCurvePublicKey(new Uint8Array([9]))).toThrow('Invalid curve public key length')

    const normalized = (strictBuilder as never as {
      normalizeCurvePublicKey: (publicKey: Uint8Array) => Uint8Array
    }).normalizeCurvePublicKey(new Uint8Array(32).fill(7))
    expect(normalized.length).toBe(33)
    expect(normalized[0]).toBe(0x05)

    expect(() => (strictBuilder as never as {
      resolveRemoteDhPublicKey: (publicKey: Uint8Array, label: string) => Uint8Array
    }).resolveRemoteDhPublicKey(new Uint8Array([9]), 'remote')).toThrow('Invalid remote length for X25519 DH')
  })

  it('covers legacy suite and session-cipher invalid key branches', () => {
    expect(() => LegacyLibsignalSuite.encryptPayload({
      cipherKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      plaintext: new Uint8Array([1]),
      associatedData: new Uint8Array([1, 2]),
    })).toThrow('Invalid associated data for legacy ciphertext encryption')

    expect(() => LegacyLibsignalSuite.decryptPayload({
      cipherKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      payload: new Uint8Array([1, 2, 3]),
      associatedData: new Uint8Array([1, 2]),
    })).toThrow('Invalid associated data for legacy ciphertext decryption')

    const cipher = new SessionCipher(cipherStorage, new ProtocolAddress('peer', 1))
    expect(() => (cipher as never as {
      resolveRemoteDhPublicKey: (remoteKey: Uint8Array) => Uint8Array
    }).resolveRemoteDhPublicKey(new Uint8Array([1]))).toThrow('Invalid remote ratchet key length for X25519 DH')
  })
})

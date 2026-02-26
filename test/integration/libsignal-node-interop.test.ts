import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import * as legacyLibsignal from 'libsignal'
import { ProtocolAddress, SessionRecord, initCrypto } from '../../src'
import { SessionBuilder as CompatSessionBuilder, SessionCipher as CompatSessionCipher } from '../../src/compat/libsignal'
import * as legacyCurve from '../../src/compat/libsignal/src/curve'

type LegacyKeyPair = { pubKey: Buffer; privKey: Buffer }

function toLegacyBuffer(value: Uint8Array | Buffer): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value)
}

function createLegacyStore(params: {
  identity: LegacyKeyPair
  registrationId: number
  preKeys: ReadonlyMap<number, LegacyKeyPair>
  signedPreKey: LegacyKeyPair
}) {
  const sessions = new Map<string, Uint8Array>()
  const preKeys = new Map(params.preKeys)

  return {
    async loadSession(id: string): Promise<InstanceType<typeof legacyLibsignal.SessionRecord> | undefined> {
      const serialized = sessions.get(id)
      if (!serialized) return undefined
      return legacyLibsignal.SessionRecord.deserialize(serialized)
    },
    async storeSession(id: string, session: InstanceType<typeof legacyLibsignal.SessionRecord>): Promise<void> {
      sessions.set(id, session.serialize())
    },
    async isTrustedIdentity(): Promise<boolean> {
      return true
    },
    async loadPreKey(id: number | string): Promise<{ privKey: Buffer; pubKey: Buffer } | undefined> {
      const keyId = typeof id === 'number' ? id : Number(id)
      const preKey = preKeys.get(keyId)
      if (!preKey) return undefined
      return { privKey: preKey.privKey, pubKey: preKey.pubKey }
    },
    async removePreKey(id: number): Promise<void> {
      preKeys.delete(id)
    },
    loadSignedPreKey(): { privKey: Buffer; pubKey: Buffer } {
      return {
        privKey: params.signedPreKey.privKey,
        pubKey: params.signedPreKey.pubKey,
      }
    },
    getOurRegistrationId(): number {
      return params.registrationId
    },
    getOurIdentity(): { privKey: Buffer; pubKey: Buffer } {
      return {
        privKey: params.identity.privKey,
        pubKey: params.identity.pubKey,
      }
    },
  }
}

function createSwtStore(params: {
  identity: LegacyKeyPair
  registrationId: number
  preKeys: ReadonlyMap<number, LegacyKeyPair>
  signedPreKey: LegacyKeyPair
}) {
  const sessions = new Map<string, Uint8Array>()
  const preKeys = new Map(params.preKeys)

  return {
    async loadSession(id: string): Promise<SessionRecord | undefined> {
      const serialized = sessions.get(id)
      if (!serialized) return undefined
      return SessionRecord.deserialize(serialized)
    },
    async storeSession(id: string, record: SessionRecord): Promise<void> {
      sessions.set(id, record.serialize())
    },
    async isTrustedIdentity(): Promise<boolean> {
      return true
    },
    async loadPreKey(id: number): Promise<{ privKey: Uint8Array; pubKey: Uint8Array } | undefined> {
      const preKey = preKeys.get(id)
      if (!preKey) return undefined
      return {
        privKey: preKey.privKey,
        pubKey: preKey.pubKey,
      }
    },
    async loadSignedPreKey(id: number): Promise<{ privKey: Uint8Array; pubKey: Uint8Array } | undefined> {
      if (id !== 1) return undefined
      return {
        privKey: params.signedPreKey.privKey,
        pubKey: params.signedPreKey.pubKey,
      }
    },
    async removePreKey(id: number): Promise<void> {
      preKeys.delete(id)
    },
    async getOurRegistrationId(): Promise<number> {
      return params.registrationId
    },
    async getOurIdentity(): Promise<{ privKey: Uint8Array; pubKey: Uint8Array }> {
      return {
        privKey: params.identity.privKey,
        pubKey: params.identity.pubKey,
      }
    },
  }
}

describe('interop with whiskeysockets/libsignal-node', () => {
  it('supports cross-encrypt/decrypt and stress message exchange', async () => {
    await initCrypto()

    const aliceIdentity = legacyCurve.generateKeyPair()
    const bobIdentity = legacyCurve.generateKeyPair()
    const bobSignedPreKey = legacyCurve.generateKeyPair()
    const bobOneTimePreKey = legacyCurve.generateKeyPair()
    const aliceSignedPreKey = legacyCurve.generateKeyPair()
    const aliceOneTimePreKey = legacyCurve.generateKeyPair()

    const aliceReg = 4001
    const bobReg = 5001

    const aliceStoreSwt = createSwtStore({
      identity: aliceIdentity,
      registrationId: aliceReg,
      preKeys: new Map([[7, aliceOneTimePreKey]]),
      signedPreKey: aliceSignedPreKey,
    })

    const bobStoreLegacy = createLegacyStore({
      identity: bobIdentity,
      registrationId: bobReg,
      preKeys: new Map([[9, bobOneTimePreKey]]),
      signedPreKey: bobSignedPreKey,
    })

    const bobPreKeyBundle = {
      registrationId: bobReg,
      identityKey: toLegacyBuffer(bobIdentity.pubKey),
      signedPreKey: {
        keyId: 1,
        publicKey: toLegacyBuffer(bobSignedPreKey.pubKey),
        signature: legacyCurve.calculateSignature(bobIdentity.privKey, bobSignedPreKey.pubKey),
      },
      preKey: {
        keyId: 9,
        publicKey: toLegacyBuffer(bobOneTimePreKey.pubKey),
      },
    }

    const aliceBuilder = new CompatSessionBuilder(aliceStoreSwt, new ProtocolAddress('bob', 1))
    const aliceCipher = new CompatSessionCipher(aliceStoreSwt, new ProtocolAddress('bob', 1))

    const bobCipher = new legacyLibsignal.SessionCipher(
      bobStoreLegacy as unknown as legacyLibsignal.SignalStorage,
      new legacyLibsignal.ProtocolAddress('alice', 1),
    )

    await aliceBuilder.initOutgoing(bobPreKeyBundle)

    const firstPacket = await aliceCipher.encrypt(Buffer.from('hello-from-swt'))
    expect(firstPacket.type).toBe(3)

    const firstPlain = await bobCipher.decryptPreKeyWhisperMessage(Buffer.from(firstPacket.body, 'binary'))
    expect(firstPlain.toString('utf8')).toBe('hello-from-swt')

    const bobReply = await bobCipher.encrypt(Buffer.from('hello-from-legacy'))
    expect(bobReply.type).toBe(1)

    const bobReplyBytes = Buffer.from(bobReply.body, 'binary')
    const bobReplyPlain = await aliceCipher.decryptWhisperMessage(bobReplyBytes)
    expect(Buffer.from(bobReplyPlain).toString('utf8')).toBe('hello-from-legacy')

    for (let i = 0; i < 120; i++) {
      if (i % 2 === 0) {
        const payload = randomBytes((i % 48) + 1)
        const encrypted = await aliceCipher.encrypt(payload)
        const wire = Buffer.from(encrypted.body, 'binary')
        const decrypted = encrypted.type === 3
          ? await bobCipher.decryptPreKeyWhisperMessage(wire)
          : await bobCipher.decryptWhisperMessage(wire)
        expect(Buffer.compare(Buffer.from(decrypted), payload)).toBe(0)
      } else {
        const payload = randomBytes((i % 64) + 1)
        const encrypted = await bobCipher.encrypt(payload)
        const wire = Buffer.from(encrypted.body, 'binary')
        const decrypted = encrypted.type === 3
          ? await aliceCipher.decryptPreKeyWhisperMessage(wire)
          : await aliceCipher.decryptWhisperMessage(wire)
        expect(Buffer.compare(Buffer.from(decrypted), payload)).toBe(0)
      }
    }
  })
})

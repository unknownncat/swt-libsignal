import { describe, expect, it } from 'vitest'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import {
  CbcHmacSuite,
  GcmSuite,
  buildDecryptTransportMacInput,
  buildTransportMacInput,
  type CryptoSuite,
  type MessageMetadata,
} from '../../src/session/cipher/crypto-suite'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionEntry, SessionRecord } from '../../src/session/record'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { SessionDecryptFailed } from '../../src/signal-errors'
import { crypto } from '../../src/crypto'

const VERSION_BYTE = 0x33
const HMAC_DERIVE_MESSAGE_KEY = Uint8Array.of(1)
const HMAC_DERIVE_CHAIN_KEY = Uint8Array.of(2)
const HKDF_INFO_MESSAGE_KEYS = new TextEncoder().encode('WhisperMessageKeys')
const ZERO32 = new Uint8Array(32)

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function sequence(length: number, start: number): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    out[i] = (start + i) & 0xff
  }
  return out
}

function deriveMessageKey(
  chain: { chainKey: { counter: number; key: Uint8Array | undefined }; messageKeys: Map<number, Uint8Array> },
  counter: number
): Uint8Array {
  if (!chain.chainKey.key) throw new Error('chain key is closed')

  let key = chain.chainKey.key
  let currentCounter = chain.chainKey.counter
  const messageKeys = new Map(chain.messageKeys)

  while (currentCounter < counter) {
    currentCounter += 1
    messageKeys.set(currentCounter, crypto.hmacSha256(key, HMAC_DERIVE_MESSAGE_KEY))
    key = crypto.hmacSha256(key, HMAC_DERIVE_CHAIN_KEY)
  }

  const messageKey = messageKeys.get(counter)
  if (!messageKey) throw new Error('unable to derive message key')
  return messageKey
}

function deriveWhisperKeys(messageKey: Uint8Array): readonly [Uint8Array, Uint8Array, Uint8Array] {
  const hkdf = crypto.hkdf(messageKey, ZERO32, HKDF_INFO_MESSAGE_KEYS, { length: 96 })
  return [hkdf.subarray(0, 32), hkdf.subarray(32, 64), hkdf.subarray(64, 96)] as const
}

function setupFixture(suite: CryptoSuite) {
  const ourIdentity = {
    pubKey: new Uint8Array(32).fill(41),
    privKey: new Uint8Array(32).fill(42),
  }
  const remoteIdentity = new Uint8Array(32).fill(43)
  const remoteEphemeral = new Uint8Array(32).fill(44)
  const localEphemeral = new Uint8Array(32).fill(45)

  const session = new SessionEntry()
  session.registrationId = 5
  session.currentRatchet = {
    ephemeralKeyPair: { pubKey: localEphemeral, privKey: new Uint8Array(32).fill(46) },
    lastRemoteEphemeralKey: remoteEphemeral,
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(47),
  }
  session.indexInfo = {
    baseKey: new Uint8Array(32).fill(48),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: remoteIdentity,
  }
  session.addChain(remoteEphemeral, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(49) },
    chainType: ChainType.RECEIVING,
    messageKeys: new Map(),
  })
  session.addChain(localEphemeral, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(50) },
    chainType: ChainType.SENDING,
    messageKeys: new Map(),
  })

  const record = new SessionRecord()
  record.setSession(session)

  const writes = { count: 0 }
  const storage = {
    loadSession: async () => record,
    storeSession: async () => { writes.count += 1 },
    getOurIdentity: async () => ourIdentity,
    isTrustedIdentity: async () => true,
    getOurRegistrationId: async () => 1,
    loadPreKey: async () => undefined,
    loadSignedPreKey: async () => undefined,
    removePreKey: async () => undefined,
  }

  return {
    suite,
    cipher: new SessionCipher(storage, new ProtocolAddress('peer', 1), { cryptoSuite: suite }),
    record,
    session,
    writes,
    ourIdentity,
    remoteEphemeral,
  }
}

function buildIncomingWhisperMessage(params: {
  suite: CryptoSuite
  session: SessionEntry
  ourIdentityPub: Uint8Array
  remoteEphemeral: Uint8Array
  counter: number
  previousCounter: number
  plaintext: Uint8Array
}): Uint8Array {
  const chain = params.session.getChain(params.remoteEphemeral)
  if (!chain) throw new Error('missing remote chain')

  const messageKey = deriveMessageKey(chain, params.counter)
  const [cipherKey, macKey, aadKey] = deriveWhisperKeys(messageKey)
  const metadata: MessageMetadata = {
    ephemeralKey: params.remoteEphemeral,
    counter: params.counter,
    previousCounter: params.previousCounter,
  }
  const associatedData = params.suite.buildAssociatedData({
    senderIdentityKey: params.session.indexInfo.remoteIdentityKey,
    receiverIdentityKey: params.ourIdentityPub,
    versionByte: VERSION_BYTE,
    message: metadata,
    aadKey,
  })
  const payload = params.suite.encryptPayload({
    cipherKey,
    macKey,
    plaintext: params.plaintext,
    associatedData,
  })

  const proto = WhisperMessageEncoder.encodeWhisperMessage({
    ephemeralKey: params.remoteEphemeral,
    counter: params.counter,
    previousCounter: params.previousCounter,
    ciphertext: payload,
  })

  const body = new Uint8Array(1 + proto.length + 8)
  body[0] = VERSION_BYTE
  body.set(proto, 1)
  const transport = buildDecryptTransportMacInput(
    params.session.indexInfo.remoteIdentityKey,
    params.ourIdentityPub,
    VERSION_BYTE,
    body
  )
  const mac = params.suite.mac(macKey, transport.macInput, 8)
  body.set(mac, 1 + proto.length)
  return body
}

function tamperCiphertextAndReMac(params: {
  suite: CryptoSuite
  body: Uint8Array
  session: SessionEntry
  ourIdentityPub: Uint8Array
  remoteEphemeral: Uint8Array
  counter: number
}): Uint8Array {
  const proto = WhisperMessageEncoder.decodeWhisperMessage(params.body.subarray(1, params.body.length - 8))
  const ciphertext = proto.ciphertext.slice()
  const tamperIndex = params.suite.name === 'gcm' ? 13 : 20
  ciphertext[tamperIndex] ^= 0x01

  const newProto = WhisperMessageEncoder.encodeWhisperMessage({
    ephemeralKey: proto.ephemeralKey,
    counter: proto.counter,
    previousCounter: proto.previousCounter,
    ciphertext,
  })
  const tampered = new Uint8Array(1 + newProto.length + 8)
  tampered[0] = VERSION_BYTE
  tampered.set(newProto, 1)

  const chain = params.session.getChain(params.remoteEphemeral)
  if (!chain) throw new Error('missing remote chain')

  const messageKey = deriveMessageKey(chain, params.counter)
  const [, macKey] = deriveWhisperKeys(messageKey)
  const transport = buildDecryptTransportMacInput(
    params.session.indexInfo.remoteIdentityKey,
    params.ourIdentityPub,
    VERSION_BYTE,
    tampered
  )
  const mac = params.suite.mac(macKey, transport.macInput, 8)
  tampered.set(mac, 1 + newProto.length)
  return tampered
}

describe('crypto suites', () => {
  it('builds identical transport MAC input on encrypt/decrypt paths', () => {
    const sender = sequence(32, 1)
    const receiver = sequence(32, 33)
    const proto = WhisperMessageEncoder.encodeWhisperMessage({
      ephemeralKey: sequence(32, 90),
      counter: 11,
      previousCounter: 7,
      ciphertext: sequence(64, 120),
    })

    const encryptedMacInput = buildTransportMacInput(sender, receiver, VERSION_BYTE, proto)
    const body = new Uint8Array(1 + proto.length + 8)
    body[0] = VERSION_BYTE
    body.set(proto, 1)
    const transport = buildDecryptTransportMacInput(sender, receiver, VERSION_BYTE, body)

    expect(transport.messageProto).toEqual(proto)
    expect(transport.macInput).toEqual(encryptedMacInput)
  })

  it('roundtrips payload encrypt/decrypt for each suite', () => {
    const suites: readonly CryptoSuite[] = [GcmSuite, CbcHmacSuite]
    const metadata: MessageMetadata = {
      ephemeralKey: sequence(32, 1),
      counter: 7,
      previousCounter: 5,
    }

    for (const suite of suites) {
      const associatedData = suite.buildAssociatedData({
        senderIdentityKey: sequence(32, 10),
        receiverIdentityKey: sequence(32, 40),
        versionByte: VERSION_BYTE,
        message: metadata,
        aadKey: sequence(32, 90),
      })
      const plaintext = new TextEncoder().encode(`suite:${suite.name}:payload`)
      const payload = suite.encryptPayload({
        cipherKey: sequence(32, 120),
        macKey: sequence(32, 160),
        plaintext,
        associatedData,
      })
      const decrypted = suite.decryptPayload({
        cipherKey: sequence(32, 120),
        macKey: sequence(32, 160),
        payload,
        associatedData,
      })

      expect(decrypted).toEqual(plaintext)
    }
  })

  it('uses deterministic vectors with fixed IVs', () => {
    const metadata: MessageMetadata = {
      ephemeralKey: sequence(32, 4),
      counter: 3,
      previousCounter: 2,
    }

    const gcmAssociatedData = GcmSuite.buildAssociatedData({
      senderIdentityKey: sequence(32, 16),
      receiverIdentityKey: sequence(32, 48),
      versionByte: VERSION_BYTE,
      message: metadata,
      aadKey: sequence(32, 80),
    })
    const gcmPayload = GcmSuite.encryptPayload({
      cipherKey: sequence(32, 112),
      macKey: sequence(32, 144),
      plaintext: new TextEncoder().encode('deterministic-gcm'),
      associatedData: gcmAssociatedData,
      iv: new Uint8Array(12).fill(9),
    })

    const cbcAssociatedData = CbcHmacSuite.buildAssociatedData({
      senderIdentityKey: sequence(32, 16),
      receiverIdentityKey: sequence(32, 48),
      versionByte: VERSION_BYTE,
      message: metadata,
      aadKey: sequence(32, 80),
    })
    const cbcPayload = CbcHmacSuite.encryptPayload({
      cipherKey: sequence(32, 112),
      macKey: sequence(32, 144),
      plaintext: new TextEncoder().encode('deterministic-cbc'),
      associatedData: cbcAssociatedData,
      iv: new Uint8Array(16).fill(10),
    })

    expect(toHex(gcmPayload)).toBe('090909090909090909090909c412b4fcc3ee4bfd92cbe18e34d98cdaf019cd55a28b2555737c1c310d39eab21f')
    expect(toHex(cbcPayload)).toBe('0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a6a7e36dfcc740c50cc0e0299d5b6e2396ba3b462b96b0ce548fb4ce2bfd24aaf3e550bc33505ff05672115d9f9f821d5ccef886b131c269d83d259ae5b241c14')
  })

  it.each([
    ['gcm', GcmSuite],
    ['cbc-hmac', CbcHmacSuite],
  ])('rejects 1-bit payload tamper without side effects (%s)', async (_name, suite) => {
    const fixture = setupFixture(suite)
    const valid = buildIncomingWhisperMessage({
      suite,
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      plaintext: new TextEncoder().encode(`bitflip-${suite.name}`),
    })

    const tampered = tamperCiphertextAndReMac({
      suite,
      body: valid,
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
    })

    const before = fixture.record.serialize()
    await expect(fixture.cipher.decryptWhisperMessage(tampered)).rejects.toBeInstanceOf(SessionDecryptFailed)
    expect(fixture.record.serialize()).toEqual(before)
    expect(fixture.writes.count).toBe(0)
  })
})

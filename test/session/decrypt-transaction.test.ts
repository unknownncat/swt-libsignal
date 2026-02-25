import { describe, expect, it } from 'vitest'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionEntry, SessionRecord } from '../../src/session/record'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { SessionDecryptFailed } from '../../src/signal-errors'
import { crypto } from '../../src/crypto'
import { initCrypto } from '../../src/curve'

const VERSION_BYTE = 0x33
const HMAC_DERIVE_MESSAGE_KEY = Uint8Array.of(1)
const HMAC_DERIVE_CHAIN_KEY = Uint8Array.of(2)
const HKDF_INFO_MESSAGE_KEYS = new TextEncoder().encode('WhisperMessageKeys')
const ZERO32 = new Uint8Array(32)

function packCiphertext(
  encrypted: { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array }
): Uint8Array {
  const out = new Uint8Array(encrypted.iv.length + encrypted.ciphertext.length + encrypted.tag.length)
  out.set(encrypted.iv, 0)
  out.set(encrypted.ciphertext, encrypted.iv.length)
  out.set(encrypted.tag, encrypted.iv.length + encrypted.ciphertext.length)
  return out
}

function deriveMessageKey(
  chain: { chainKey: { counter: number; key: Uint8Array | undefined }; messageKeys: Map<number, Uint8Array> },
  counter: number
): Uint8Array {
  if (!chain.chainKey.key) throw new Error('chain key is closed')

  let currentCounter = chain.chainKey.counter
  let key = chain.chainKey.key
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

function buildAuthenticatedWhisperMessage(params: {
  session: SessionEntry
  ourIdentityPub: Uint8Array
  remoteEphemeral: Uint8Array
  counter: number
  previousCounter: number
  plaintext?: Uint8Array
  ciphertextPayload?: Uint8Array
}): Uint8Array {
  const chain = params.session.getChain(params.remoteEphemeral)
  if (!chain) throw new Error('remote chain not found')

  const messageKey = deriveMessageKey(chain, params.counter)
  const [cipherKey, macKey, aadKey] = deriveWhisperKeys(messageKey)
  const payload = params.ciphertextPayload
    ?? packCiphertext(crypto.encrypt(cipherKey, params.plaintext ?? new Uint8Array([1, 2, 3]), { aad: aadKey.subarray(0, 16) }))

  const proto = WhisperMessageEncoder.encodeWhisperMessage({
    ephemeralKey: params.remoteEphemeral,
    counter: params.counter,
    previousCounter: params.previousCounter,
    ciphertext: payload,
  })

  // Mirrors SessionCipher.doDecryptWhisperMessage MAC input sizing (messageEnd + 67).
  const macInput = new Uint8Array(proto.length + 68)
  macInput.set(params.session.indexInfo.remoteIdentityKey, 0)
  macInput.set(params.ourIdentityPub, 33)
  macInput[66] = VERSION_BYTE
  macInput.set(proto, 67)
  const mac = crypto.hmacSha256(macKey, macInput)

  const body = new Uint8Array(1 + proto.length + 8)
  body[0] = VERSION_BYTE
  body.set(proto, 1)
  body.set(mac.subarray(0, 8), 1 + proto.length)
  return body
}

function buildMaliciousRatchetStepMessage(params: {
  remoteEphemeral: Uint8Array
  counter: number
  previousCounter: number
  ciphertext: Uint8Array
}): Uint8Array {
  const proto = WhisperMessageEncoder.encodeWhisperMessage({
    ephemeralKey: params.remoteEphemeral,
    counter: params.counter,
    previousCounter: params.previousCounter,
    ciphertext: params.ciphertext,
  })

  const body = new Uint8Array(1 + proto.length + 8)
  body[0] = VERSION_BYTE
  body.set(proto, 1)
  body.set(new Uint8Array(8).fill(0xaa), 1 + proto.length)
  return body
}

function setupFixture() {
  const ourIdentity = {
    pubKey: new Uint8Array(32).fill(21),
    privKey: new Uint8Array(32).fill(22),
  }
  const remoteIdentity = new Uint8Array(32).fill(23)
  const remoteEphemeral = new Uint8Array(32).fill(24)
  const localEphemeral = new Uint8Array(32).fill(25)

  const session = new SessionEntry()
  session.registrationId = 99
  session.currentRatchet = {
    ephemeralKeyPair: { pubKey: localEphemeral, privKey: new Uint8Array(32).fill(26) },
    lastRemoteEphemeralKey: remoteEphemeral,
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(27),
  }
  session.indexInfo = {
    baseKey: new Uint8Array(32).fill(28),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: remoteIdentity,
  }
  session.addChain(remoteEphemeral, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(29) },
    chainType: ChainType.RECEIVING,
    messageKeys: new Map(),
  })
  session.addChain(localEphemeral, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(30) },
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
    cipher: new SessionCipher(storage, new ProtocolAddress('peer', 1)),
    record,
    session,
    writes,
    ourIdentity,
    remoteEphemeral,
  }
}

describe('SessionCipher decrypt transactionality', () => {
  it('rejects invalid MAC repeatedly without mutating state and still decrypts valid input later', async () => {
    const fixture = setupFixture()
    const valid = buildAuthenticatedWhisperMessage({
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      plaintext: new TextEncoder().encode('valid-after-failures'),
    })

    const badMac = valid.slice()
    badMac[badMac.length - 1] ^= 0x01
    const before = fixture.record.serialize()

    for (let i = 0; i < 3; i++) {
      await expect(fixture.cipher.decryptWhisperMessage(badMac)).rejects.toBeInstanceOf(SessionDecryptFailed)
      expect(fixture.record.serialize()).toEqual(before)
    }

    expect(fixture.writes.count).toBe(0)
    const plaintext = await fixture.cipher.decryptWhisperMessage(valid)
    expect(new TextDecoder().decode(plaintext)).toBe('valid-after-failures')
    expect(fixture.writes.count).toBe(1)
  })

  it('rejects truncated ciphertext without mutating state', async () => {
    const fixture = setupFixture()
    const truncated = buildAuthenticatedWhisperMessage({
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      ciphertextPayload: new Uint8Array(20).fill(7),
    })

    const before = fixture.record.serialize()
    await expect(fixture.cipher.decryptWhisperMessage(truncated)).rejects.toBeInstanceOf(SessionDecryptFailed)
    expect(fixture.record.serialize()).toEqual(before)
    expect(fixture.writes.count).toBe(0)
  })

  it('rejects replay without advancing state after first successful decrypt', async () => {
    const fixture = setupFixture()
    const body = buildAuthenticatedWhisperMessage({
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      plaintext: new TextEncoder().encode('replay-once'),
    })

    const first = await fixture.cipher.decryptWhisperMessage(body)
    expect(new TextDecoder().decode(first)).toBe('replay-once')

    const beforeReplay = fixture.record.serialize()
    await expect(fixture.cipher.decryptWhisperMessage(body)).rejects.toBeInstanceOf(SessionDecryptFailed)
    expect(fixture.record.serialize()).toEqual(beforeReplay)

    const chain = fixture.session.getChain(fixture.remoteEphemeral)
    expect(chain?.chainKey.counter).toBe(1)
    expect(chain?.messageKeys.size).toBe(0)
  })

  it('supports out-of-order messages within window without burning extra state', async () => {
    const fixture = setupFixture()
    const first = buildAuthenticatedWhisperMessage({
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 1,
      previousCounter: 0,
      plaintext: new TextEncoder().encode('first'),
    })
    const second = buildAuthenticatedWhisperMessage({
      session: fixture.session,
      ourIdentityPub: fixture.ourIdentity.pubKey,
      remoteEphemeral: fixture.remoteEphemeral,
      counter: 2,
      previousCounter: 0,
      plaintext: new TextEncoder().encode('second'),
    })

    const secondPlain = await fixture.cipher.decryptWhisperMessage(second)
    expect(new TextDecoder().decode(secondPlain)).toBe('second')

    let chain = fixture.session.getChain(fixture.remoteEphemeral)
    expect(chain?.chainKey.counter).toBe(2)
    expect(chain?.messageKeys.has(1)).toBe(true)
    expect(chain?.messageKeys.has(2)).toBe(false)

    const firstPlain = await fixture.cipher.decryptWhisperMessage(first)
    expect(new TextDecoder().decode(firstPlain)).toBe('first')

    chain = fixture.session.getChain(fixture.remoteEphemeral)
    expect(chain?.chainKey.counter).toBe(2)
    expect(chain?.messageKeys.has(1)).toBe(false)
    expect(chain?.messageKeys.size).toBe(0)
  })

  it('rolls back ratchet-step attempts from malicious messages', async () => {
    await initCrypto()
    const fixture = setupFixture()
    const forcedRemoteEphemeral = new Uint8Array(32).fill(61)
    const malicious = buildMaliciousRatchetStepMessage({
      remoteEphemeral: forcedRemoteEphemeral,
      counter: 0,
      previousCounter: 0,
      ciphertext: new Uint8Array(28).fill(9),
    })

    const before = fixture.record.serialize()
    await expect(fixture.cipher.decryptWhisperMessage(malicious)).rejects.toBeInstanceOf(SessionDecryptFailed)
    expect(fixture.record.serialize()).toEqual(before)
    expect(fixture.writes.count).toBe(0)
    expect(fixture.session.getChain(forcedRemoteEphemeral)).toBeUndefined()
    expect(fixture.session.currentRatchet.lastRemoteEphemeralKey).toEqual(fixture.remoteEphemeral)
  })
})

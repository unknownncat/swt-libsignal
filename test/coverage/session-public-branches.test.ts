import { afterEach, describe, expect, it, vi } from 'vitest'
import * as proto from '../../src/proto'
import { crypto } from '../../src/crypto'
import { signalCrypto } from '../../src/curve'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { CbcHmacSuite, GcmSuite } from '../../src/session/cipher/crypto-suite'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import { SessionEntry, SessionRecord } from '../../src/session/record'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { SessionDecryptFailed, SessionStateError, UntrustedIdentityKeyError } from '../../src/signal-errors'
import { makeLibSignalRepository } from '../../src/signal/libsignal'
import { GroupCipher, GroupSessionBuilder, SenderKeyRecord } from '../../src/signal/group'
import { createSignalAsync } from '../../src/public/dual-api'

afterEach(() => {
  vi.restoreAllMocks()
})

function makeSessionEntry(chainType: ChainType = ChainType.SENDING): SessionEntry {
  const session = new SessionEntry()
  const eph = new Uint8Array(32).fill(7)

  session.registrationId = 1
  session.currentRatchet = {
    ephemeralKeyPair: { pubKey: eph, privKey: new Uint8Array(32).fill(8) },
    lastRemoteEphemeralKey: new Uint8Array(32).fill(9),
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(10),
  }
  session.indexInfo = {
    baseKey: new Uint8Array(32).fill(11),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: new Uint8Array(32).fill(12),
  }

  session.addChain(eph, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(13) },
    chainType,
    messageKeys: new Map(),
  })

  return session
}

function makeRecord(session: SessionEntry): SessionRecord {
  const record = new SessionRecord()
  record.setSession(session)
  return record
}

function makeCipherStorage(record?: SessionRecord) {
  let currentRecord = record

  return {
    loadSession: vi.fn(async () => currentRecord),
    storeSession: vi.fn(async (_addr: string, next: SessionRecord) => { currentRecord = next }),
    getOurIdentity: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(64).fill(2) })),
    isTrustedIdentity: vi.fn(async () => true),
    getOurRegistrationId: vi.fn(async () => 77),
    loadPreKey: vi.fn(async () => undefined),
    loadSignedPreKey: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(3), privKey: new Uint8Array(32).fill(4) })),
    removePreKey: vi.fn(async () => undefined),
  }
}

function makeBuilderStorage() {
  return {
    isTrustedIdentity: vi.fn(async () => true),
    loadSession: vi.fn(async () => undefined),
    storeSession: vi.fn(async () => undefined),
    getOurIdentity: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(5), privKey: new Uint8Array(64).fill(6) })),
    loadPreKey: vi.fn(async () => undefined),
    loadSignedPreKey: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(7), privKey: new Uint8Array(32).fill(8) })),
  }
}

describe('coverage - session/public heavy branches', () => {
  it('covers encoding and crypto-suite guard branches', () => {
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array())).toThrow('WhisperMessage payload size is invalid')
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array())).toThrow('PreKeyWhisperMessage payload size is invalid')

    const whisperDecode = vi.spyOn(proto.WhisperMessageCodec, 'decode')
    whisperDecode.mockReturnValueOnce({ counter: 1, previousCounter: 1 } as never)
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([1]))).toThrow('WhisperMessage missing required binary fields')

    whisperDecode.mockReturnValueOnce({ ephemeralKey: new Uint8Array([1]), ciphertext: new Uint8Array([1]) } as never)
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([1]))).toThrow('WhisperMessage missing required numeric fields')

    whisperDecode.mockReturnValueOnce({ ephemeralKey: new Uint8Array([1]), ciphertext: new Uint8Array([1]), counter: -1, previousCounter: 0 } as never)
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([1]))).toThrow('WhisperMessage counters must be non-negative integers')

    whisperDecode.mockReturnValueOnce({
      ephemeralKey: new Uint8Array(),
      ciphertext: new Uint8Array([1]),
      counter: 0,
      previousCounter: 0,
    } as never)
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([1]))).toThrow('WhisperMessage.ephemeralKey must not be empty')

    whisperDecode.mockReturnValueOnce({
      ephemeralKey: new Uint8Array(65).fill(1),
      ciphertext: new Uint8Array([1]),
      counter: 0,
      previousCounter: 0,
    } as never)
    expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([1]))).toThrow('WhisperMessage.ephemeralKey exceeds maximum allowed size')
    whisperDecode.mockRestore()

    const preDecode = vi.spyOn(proto.PreKeyWhisperMessageCodec, 'decode')
    preDecode.mockReturnValueOnce({ signedPreKeyId: 1, registrationId: 1 } as never)
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array([1]))).toThrow('PreKeyWhisperMessage missing required binary fields')

    preDecode.mockReturnValueOnce({ identityKey: new Uint8Array([1]), baseKey: new Uint8Array([1]), message: new Uint8Array([1]) } as never)
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array([1]))).toThrow('PreKeyWhisperMessage missing required numeric fields')

    preDecode.mockReturnValueOnce({ identityKey: new Uint8Array([1]), baseKey: new Uint8Array([1]), message: new Uint8Array([1]), signedPreKeyId: -1, registrationId: 1 } as never)
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array([1]))).toThrow('PreKeyWhisperMessage numeric fields must be non-negative integers')

    preDecode.mockReturnValueOnce({
      identityKey: new Uint8Array(),
      baseKey: new Uint8Array([1]),
      message: new Uint8Array([1]),
      signedPreKeyId: 1,
      registrationId: 1,
    } as never)
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array([1]))).toThrow('PreKeyWhisperMessage.identityKey must not be empty')

    preDecode.mockReturnValueOnce({
      identityKey: new Uint8Array([1]),
      baseKey: new Uint8Array([1]),
      message: new Uint8Array(512 * 1024 + 1),
      signedPreKeyId: 1,
      registrationId: 1,
    } as never)
    expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(new Uint8Array([1]))).toThrow('PreKeyWhisperMessage.message exceeds maximum allowed size')
    preDecode.mockRestore()

    expect(() => GcmSuite.decryptPayload({
      cipherKey: new Uint8Array(32).fill(1),
      macKey: new Uint8Array(32).fill(2),
      payload: new Uint8Array(1),
      associatedData: new Uint8Array([1]),
    })).toThrow('Invalid ciphertext payload')

    expect(() => CbcHmacSuite.encryptPayload({
      cipherKey: new Uint8Array(32).fill(1),
      macKey: new Uint8Array(32).fill(2),
      plaintext: new Uint8Array([1]),
      associatedData: new Uint8Array([2]),
      iv: new Uint8Array(1),
    })).toThrow('IV must be 16 bytes for AES-CBC')

    expect(() => CbcHmacSuite.decryptPayload({
      cipherKey: new Uint8Array(32).fill(1),
      macKey: new Uint8Array(32).fill(2),
      payload: new Uint8Array(1),
      associatedData: new Uint8Array([2]),
    })).toThrow('Invalid ciphertext payload')

    const badBlock = new Uint8Array(16 + 17 + 32)
    expect(() => CbcHmacSuite.decryptPayload({
      cipherKey: new Uint8Array(32).fill(1),
      macKey: new Uint8Array(32).fill(2),
      payload: badBlock,
      associatedData: new Uint8Array([2]),
    })).toThrow('Invalid ciphertext payload')
  })

  it('covers SessionBuilder guards and strict/legacy conversion branches', async () => {
    const storage = makeBuilderStorage()
    const addr = new ProtocolAddress('peer', 1)
    const builder = new SessionBuilder(storage, addr)
    const builderAny = builder as never as {
      assertNotAborted: (signal: AbortSignal) => void
      resolveOurIdentityDhPrivateKey: (value: Uint8Array) => Uint8Array
      resolveTheirIdentityDhPublicKey: (value: Uint8Array) => Uint8Array
    }

    const abortedError = new AbortController()
    abortedError.abort(new Error('abort-error'))
    expect(() => builderAny.assertNotAborted(abortedError.signal)).toThrow('abort-error')

    const abortedValue = new AbortController()
    abortedValue.abort('abort-value')
    expect(() => builderAny.assertNotAborted(abortedValue.signal)).toThrow('Operation aborted')

    await expect(builder.initOutgoing({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
    } as never)).rejects.toThrow('Missing device.signedPreKey')

    await expect(builder.initOutgoing({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32).fill(2), signature: new Uint8Array() },
    })).rejects.toThrow('Invalid device.signedPreKey.signature')

    const validBundle = {
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32).fill(2), signature: new Uint8Array(64).fill(3) },
    }

    storage.isTrustedIdentity.mockResolvedValueOnce(false)
    await expect(builder.initOutgoing(validBundle)).rejects.toBeInstanceOf(UntrustedIdentityKeyError)

    const verifySpy = vi.spyOn(signalCrypto, 'verify').mockReturnValueOnce(false)
    await expect(builder.initOutgoing(validBundle)).rejects.toThrow('Invalid signature on signedPreKey')
    verifySpy.mockRestore()

    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const legacyDefaultWarn = new SessionBuilder(storage, addr, { compatMode: 'legacy' })
    expect((legacyDefaultWarn as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(32))).toEqual(new Uint8Array(32))
    expect(consoleWarn).toHaveBeenCalled()
    consoleWarn.mockRestore()

    const strict = new SessionBuilder(storage, addr, { compatMode: 'strict', warn: vi.fn() })

    const privateConvertSpy = vi.spyOn(signalCrypto, 'convertIdentityPrivateToX25519')
    privateConvertSpy.mockImplementationOnce(() => { throw new Error('bad-conversion') })
    expect(() => (strict as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(64))).toThrow('X3DH strict mode rejected local identity private key conversion')
    privateConvertSpy.mockImplementationOnce(() => { throw 'bad-conversion' as never })
    expect(() => (strict as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(64))).toThrow('X3DH strict mode rejected local identity private key conversion')
    expect(() => (strict as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(32))).toThrow('X3DH strict mode requires a 64-byte Ed25519 local identity private key')
    expect(() => (strict as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(10))).toThrow('Invalid local identity private key length')

    const legacyWarn = vi.fn()
    const legacy = new SessionBuilder(storage, addr, { compatMode: 'legacy', warn: legacyWarn })
    expect((legacy as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(32))).toEqual(new Uint8Array(32))
    ;(legacy as never as { resolveOurIdentityDhPrivateKey: (v: Uint8Array) => Uint8Array }).resolveOurIdentityDhPrivateKey(new Uint8Array(32))
    expect(legacyWarn).toHaveBeenCalledTimes(1)

    expect(() => (strict as never as { resolveTheirIdentityDhPublicKey: (v: Uint8Array) => Uint8Array }).resolveTheirIdentityDhPublicKey(new Uint8Array(31))).toThrow('Invalid remote identity public key length')

    const publicConvertSpy = vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519')
    publicConvertSpy.mockImplementationOnce(() => { throw new Error('bad-public-conversion') })
    expect(() => (strict as never as { resolveTheirIdentityDhPublicKey: (v: Uint8Array) => Uint8Array }).resolveTheirIdentityDhPublicKey(new Uint8Array(32))).toThrow('X3DH strict mode rejected remote identity key conversion')
    publicConvertSpy.mockImplementationOnce(() => { throw 'bad-public-conversion' as never })
    expect(() => (strict as never as { resolveTheirIdentityDhPublicKey: (v: Uint8Array) => Uint8Array }).resolveTheirIdentityDhPublicKey(new Uint8Array(32))).toThrow('X3DH strict mode rejected remote identity key conversion')

    const legacyPublicWarn = vi.fn()
    const legacyPublic = new SessionBuilder(storage, addr, { compatMode: 'legacy', warn: legacyPublicWarn })
    publicConvertSpy.mockImplementationOnce(() => { throw new Error('fallback') })
    expect((legacyPublic as never as { resolveTheirIdentityDhPublicKey: (v: Uint8Array) => Uint8Array }).resolveTheirIdentityDhPublicKey(new Uint8Array(32))).toEqual(new Uint8Array(32))
    expect(legacyPublicWarn).toHaveBeenCalledTimes(1)
  })

  it('covers SessionBuilder.initIncoming early exits and open-session close path', async () => {
    const storage = makeBuilderStorage()
    const addr = new ProtocolAddress('peer', 1)
    const builder = new SessionBuilder(storage, addr)

    const existingRecord = new SessionRecord()
    const existing = makeSessionEntry(ChainType.RECEIVING)
    existing.indexInfo.baseKey = new Uint8Array(32).fill(55)
    existingRecord.setSession(existing)

    const duplicateMessage = {
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      baseKey: existing.indexInfo.baseKey,
      signedPreKeyId: 1,
      message: new Uint8Array([1]),
    }

    await expect(builder.initIncoming(existingRecord, duplicateMessage)).resolves.toBeUndefined()

    storage.isTrustedIdentity.mockResolvedValueOnce(false)
    await expect(builder.initIncoming(new SessionRecord(), {
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      baseKey: new Uint8Array(32).fill(3),
      signedPreKeyId: 1,
      message: new Uint8Array([1]),
    })).rejects.toBeInstanceOf(UntrustedIdentityKeyError)

    storage.isTrustedIdentity.mockResolvedValue(true)
    vi.spyOn(signalCrypto, 'calculateAgreement').mockReturnValue(new Uint8Array(32).fill(9))
    vi.spyOn(signalCrypto, 'convertIdentityPrivateToX25519').mockReturnValue(new Uint8Array(32).fill(1) as never)
    vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519').mockReturnValue(new Uint8Array(32).fill(2) as never)
    vi.spyOn(signalCrypto, 'generateDHKeyPair').mockResolvedValue({ publicKey: new Uint8Array(32).fill(4), privateKey: new Uint8Array(32).fill(5) } as never)

    const recordWithOpen = new SessionRecord()
    const oldOpen = makeSessionEntry(ChainType.RECEIVING)
    oldOpen.indexInfo.baseKey = new Uint8Array(32).fill(66)
    recordWithOpen.setSession(oldOpen)

    await builder.initIncoming(recordWithOpen, {
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      baseKey: new Uint8Array(32).fill(77),
      signedPreKeyId: 1,
      message: new Uint8Array([1]),
    })

    expect(oldOpen.indexInfo.closed).not.toBe(-1)
  })

  it('covers SessionBuilder.initOutgoing branch that closes an existing open session', async () => {
    const storage = makeBuilderStorage()
    const addr = new ProtocolAddress('peer', 1)
    const builder = new SessionBuilder(storage, addr)

    const oldOpen = makeSessionEntry(ChainType.RECEIVING)
    const existingRecord = new SessionRecord()
    existingRecord.setSession(oldOpen)
    storage.loadSession.mockResolvedValue(existingRecord)

    vi.spyOn(signalCrypto, 'verify').mockReturnValue(true)
    vi.spyOn(signalCrypto, 'calculateAgreement').mockReturnValue(new Uint8Array(32).fill(9))
    vi.spyOn(signalCrypto, 'convertIdentityPrivateToX25519').mockReturnValue(new Uint8Array(32).fill(1) as never)
    vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519').mockReturnValue(new Uint8Array(32).fill(2) as never)
    vi.spyOn(signalCrypto, 'generateDHKeyPair').mockResolvedValue({ publicKey: new Uint8Array(32).fill(4), privateKey: new Uint8Array(32).fill(5) } as never)

    await builder.initOutgoing({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32).fill(2), signature: new Uint8Array(64).fill(3) },
    })

    expect(oldOpen.indexInfo.closed).not.toBe(-1)
    expect(oldOpen.toString()).toContain('SessionEntry')

    const closedRecord = new SessionRecord()
    const alreadyClosed = makeSessionEntry(ChainType.RECEIVING)
    alreadyClosed.indexInfo.closed = 123
    closedRecord.setSession(alreadyClosed)
    storage.loadSession.mockResolvedValueOnce(closedRecord)

    await builder.initOutgoing({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32).fill(2), signature: new Uint8Array(64).fill(3) },
    })
    expect(alreadyClosed.indexInfo.closed).toBe(123)
  })

})

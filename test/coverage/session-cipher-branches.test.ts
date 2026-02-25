import { afterEach, describe, expect, it, vi } from 'vitest'
import * as encoding from '../../src/session/cipher/encoding'
import { crypto } from '../../src/crypto'
import { ProtocolAddress } from '../../src/protocol_address'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { CbcHmacSuite, GcmSuite } from '../../src/session/cipher/crypto-suite'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { SessionEntry, SessionRecord } from '../../src/session/record'
import { SessionDecryptFailed, SessionError, SessionStateError, UntrustedIdentityKeyError } from '../../src/signal-errors'

afterEach(() => {
  vi.restoreAllMocks()
})

function makeSession(chainType: ChainType = ChainType.SENDING): SessionEntry {
  const session = new SessionEntry()
  const localEph = new Uint8Array(32).fill(11)
  const remoteEph = new Uint8Array(32).fill(22)

  session.registrationId = 123
  session.currentRatchet = {
    ephemeralKeyPair: { pubKey: localEph, privKey: new Uint8Array(32).fill(33) },
    lastRemoteEphemeralKey: remoteEph,
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(44),
  }
  session.indexInfo = {
    baseKey: new Uint8Array(32).fill(55),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: new Uint8Array(32).fill(66),
  }

  session.addChain(localEph, {
    chainKey: { counter: 0, key: new Uint8Array(32).fill(77) },
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

function makeStorage(record?: SessionRecord) {
  let current = record
  return {
    loadSession: vi.fn(async () => current),
    storeSession: vi.fn(async (_addr: string, next: SessionRecord) => { current = next }),
    getOurIdentity: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(64).fill(2) })),
    isTrustedIdentity: vi.fn(async () => true),
    getOurRegistrationId: vi.fn(async () => 7),
    loadPreKey: vi.fn(async () => undefined),
    loadSignedPreKey: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(3), privKey: new Uint8Array(32).fill(4) })),
    removePreKey: vi.fn(async () => undefined),
  }
}

describe('coverage - session cipher branches', () => {
  it('covers constructor, warning and basic private guards', async () => {
    expect(() => new SessionCipher(makeStorage() as never, {} as never)).toThrow('protocolAddress must be a ProtocolAddress')

    const warnLegacy = vi.fn()
    const legacyCipher = new SessionCipher(makeStorage(), new ProtocolAddress('peer', 1), {
      compatMode: 'legacy',
      warn: warnLegacy,
    })
    expect(legacyCipher.toString()).toContain('SessionCipher')

    // warn once in legacy + cbc-hmac path
    const legacyAny = legacyCipher as never as {
      warnLegacyCbcHmacUsageOnce: () => void
      _encodeTupleByte: (a: number, b: number) => number
      getRecord: () => Promise<unknown>
      assertNotAborted: (signal: AbortSignal) => void
    }
    legacyAny.warnLegacyCbcHmacUsageOnce()
    expect(warnLegacy).toHaveBeenCalledTimes(1)

    // legacy + non-cbc suite early return branch
    new SessionCipher(makeStorage(), new ProtocolAddress('peer', 1), {
      compatMode: 'legacy',
      cryptoSuite: GcmSuite,
      warn: vi.fn(),
    })

    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    new SessionCipher(makeStorage(), new ProtocolAddress('peer', 2), {
      compatMode: 'legacy',
    })
    expect(consoleWarn).toHaveBeenCalled()
    consoleWarn.mockRestore()

    expect(() => legacyAny._encodeTupleByte(16, 0)).toThrow('Numbers must be 4 bits or less')

    const badStore = makeStorage() as ReturnType<typeof makeStorage> & { loadSession: () => Promise<unknown> }
    badStore.loadSession = vi.fn(async () => ({}))
    const badCipher = new SessionCipher(badStore, new ProtocolAddress('peer', 1))
    await expect((badCipher as never as { getRecord: () => Promise<unknown> }).getRecord()).rejects.toThrow('SessionRecord type expected from loadSession')

    const abortedError = new AbortController()
    abortedError.abort(new Error('abort-error'))
    expect(() => legacyAny.assertNotAborted(abortedError.signal)).toThrow('abort-error')

    const abortedValue = new AbortController()
    abortedValue.abort('abort-value')
    expect(() => legacyAny.assertNotAborted(abortedValue.signal)).toThrow('Operation aborted')
  })

  it('covers encrypt guard branches and successful type=1 path', async () => {
    const addr = new ProtocolAddress('peer', 1)

    const noRecordCipher = new SessionCipher(makeStorage(undefined), addr)
    await expect(noRecordCipher.encrypt(new Uint8Array([1]))).rejects.toBeInstanceOf(SessionError)

    const closed = makeSession(ChainType.SENDING)
    closed.indexInfo.closed = 1
    const closedCipher = new SessionCipher(makeStorage(makeRecord(closed)), addr)
    await expect(closedCipher.encrypt(new Uint8Array([1]))).rejects.toThrow('No open session')

    const untrustedStorage = makeStorage(makeRecord(makeSession(ChainType.SENDING)))
    untrustedStorage.isTrustedIdentity.mockResolvedValue(false)
    const untrustedCipher = new SessionCipher(untrustedStorage, addr)
    await expect(untrustedCipher.encrypt(new Uint8Array([1]))).rejects.toBeInstanceOf(UntrustedIdentityKeyError)

    const receivingCipher = new SessionCipher(makeStorage(makeRecord(makeSession(ChainType.RECEIVING))), addr)
    await expect(receivingCipher.encrypt(new Uint8Array([1]))).rejects.toBeInstanceOf(SessionStateError)

    const missingMessageKeySession = makeSession(ChainType.SENDING)
    const missingMessageKeyCipher = new SessionCipher(makeStorage(makeRecord(missingMessageKeySession)), addr)
    vi.spyOn(missingMessageKeyCipher as never as { fillMessageKeys: (...args: unknown[]) => void }, 'fillMessageKeys')
      .mockImplementation(() => undefined)
    await expect(missingMessageKeyCipher.encrypt(new Uint8Array([1]))).rejects.toThrow('Message key not generated')

    const badDeriveSession = makeSession(ChainType.SENDING)
    const badDeriveCipher = new SessionCipher(makeStorage(makeRecord(badDeriveSession)), addr)
    vi.spyOn(badDeriveCipher as never as { deriveSecrets: (...args: unknown[]) => Uint8Array[] }, 'deriveSecrets')
      .mockReturnValue([new Uint8Array(1), new Uint8Array(32), new Uint8Array(32)])
    await expect(badDeriveCipher.encrypt(new Uint8Array([1]))).rejects.toThrow('Invalid key derivation')

    const okSession = makeSession(ChainType.SENDING)
    delete okSession.pendingPreKey
    const okCipher = new SessionCipher(makeStorage(makeRecord(okSession)), addr)
    const encrypted = await okCipher.encrypt(new Uint8Array([9, 8, 7]))
    expect(encrypted.type).toBe(1)
  })

  it('covers decryptWhisper trusted-identity failure', async () => {
    const session = makeSession(ChainType.RECEIVING)
    const record = makeRecord(session)
    const storage = makeStorage(record)
    storage.isTrustedIdentity.mockResolvedValue(false)

    const cipher = new SessionCipher(storage, new ProtocolAddress('peer', 1))
    vi.spyOn(cipher as never as { decryptWithSessions: (...args: unknown[]) => Promise<unknown> }, 'decryptWithSessions')
      .mockResolvedValue({ session, plaintext: new Uint8Array([1]) })

    await expect(cipher.decryptWhisperMessage(new Uint8Array([1]))).rejects.toBeInstanceOf(UntrustedIdentityKeyError)
  })

  it('covers decryptPreKey guards, missing session, and removePreKey fallback', async () => {
    const storage = makeStorage()
    const cipher = new SessionCipher(storage, new ProtocolAddress('peer', 1))

    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x44, 0x00]))).rejects.toThrow('Incompatible version number on PreKeyWhisperMessage')

    const decodeSpy = vi.spyOn(encoding.WhisperMessageEncoder, 'decodePreKeyWhisperMessage')
    decodeSpy.mockReturnValueOnce({
      registrationId: 1,
      baseKey: new Uint8Array(32).fill(1),
      signedPreKeyId: 1,
      message: new Uint8Array([1]),
    } as never)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Missing or empty identityKey in PreKeyWhisperMessage')

    decodeSpy.mockReturnValueOnce({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKeyId: 1,
      message: new Uint8Array([1]),
    } as never)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Missing or empty baseKey in PreKeyWhisperMessage')

    decodeSpy.mockReturnValueOnce({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKeyId: 1,
      baseKey: new Uint8Array(32).fill(2),
    } as never)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Missing or empty message in PreKeyWhisperMessage')

    decodeSpy.mockReturnValueOnce({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      baseKey: new Uint8Array(32).fill(2),
      message: new Uint8Array([1]),
    } as never)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Missing signedPreKeyId in PreKeyWhisperMessage')

    decodeSpy.mockReturnValueOnce({
      identityKey: new Uint8Array(32).fill(1),
      signedPreKeyId: 1,
      baseKey: new Uint8Array(32).fill(2),
      message: new Uint8Array([1]),
    } as never)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Missing registrationId in PreKeyWhisperMessage')

    decodeSpy.mockReturnValueOnce({
      identityKey: new Uint8Array(32).fill(1),
      registrationId: 1,
      signedPreKeyId: 1,
      baseKey: new Uint8Array(32).fill(2),
      message: new Uint8Array([1]),
    } as never)
    vi.spyOn(SessionBuilder.prototype, 'initIncoming').mockResolvedValueOnce(undefined)
    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x01]))).rejects.toThrow('Session not initialized')

    const decodeForSuccess = vi.spyOn(encoding.WhisperMessageEncoder, 'decodePreKeyWhisperMessage')
      .mockReturnValue({
        identityKey: new Uint8Array(32).fill(1),
        registrationId: 1,
        signedPreKeyId: 1,
        preKeyId: 9,
        baseKey: new Uint8Array(32).fill(9),
        message: new Uint8Array([1]),
      } as never)

    vi.spyOn(SessionBuilder.prototype, 'initIncoming').mockImplementationOnce(async (record, message) => {
      const entry = makeSession(ChainType.RECEIVING)
      entry.indexInfo.baseKey = message.baseKey
      record.setSession(entry)
      return 9
    })
    vi.spyOn(cipher as never as { doDecryptWhisperMessage: (...args: unknown[]) => Promise<Uint8Array> }, 'doDecryptWhisperMessage')
      .mockResolvedValue(new Uint8Array([4, 4, 4]))

    await expect(cipher.decryptPreKeyWhisperMessage(new Uint8Array([0x33, 0x02]))).resolves.toEqual(new Uint8Array([4, 4, 4]))
    expect(storage.removePreKey).toHaveBeenCalledWith(9)

    decodeForSuccess.mockRestore()
  })

  it('covers closeOpenSession and decrypt helpers edge branches', async () => {
    const noRecordStorage = makeStorage(undefined)
    const noRecordCipher = new SessionCipher(noRecordStorage, new ProtocolAddress('peer', 1))
    await expect(noRecordCipher.closeOpenSession()).resolves.toBeUndefined()

    const closedSession = makeSession(ChainType.RECEIVING)
    closedSession.indexInfo.closed = 1
    const noOpenStorage = makeStorage(makeRecord(closedSession))
    const noOpenCipher = new SessionCipher(noOpenStorage, new ProtocolAddress('peer', 1))
    await expect(noOpenCipher.closeOpenSession()).resolves.toBeUndefined()

    await expect((noOpenCipher as never as { decryptWithSessions: (d: Uint8Array, s: SessionEntry[]) => Promise<unknown> })
      .decryptWithSessions(new Uint8Array([1]), []))
      .rejects.toThrow('No sessions available')

    const failingSession = makeSession(ChainType.RECEIVING)
    vi.spyOn(noOpenCipher as never as { doDecryptWhisperMessage: (...args: unknown[]) => Promise<Uint8Array> }, 'doDecryptWhisperMessage')
      .mockRejectedValueOnce('non-error' as never)

    await expect((noOpenCipher as never as { decryptWithSessions: (d: Uint8Array, s: SessionEntry[]) => Promise<unknown> })
      .decryptWithSessions(new Uint8Array([1]), [failingSession]))
      .rejects.toBeInstanceOf(SessionDecryptFailed)

    await expect((noOpenCipher as never as { doDecryptWhisperMessage: (d: Uint8Array, s: SessionEntry) => Promise<Uint8Array> })
      .doDecryptWhisperMessage(new Uint8Array([0]), failingSession))
      .rejects.toThrow('Invalid WhisperMessage')

    await expect((noOpenCipher as never as { doDecryptWhisperMessage: (d: Uint8Array, s: SessionEntry) => Promise<Uint8Array> })
      .doDecryptWhisperMessage(new Uint8Array([0x44, 0, 0, 0, 0, 0, 0, 0, 0]), failingSession))
      .rejects.toThrow('Incompatible version number on WhisperMessage')

    const sendingSession = makeSession(ChainType.SENDING)
    const remoteEph = sendingSession.currentRatchet.ephemeralKeyPair.pubKey
    vi.spyOn(encoding.WhisperMessageEncoder, 'decodeWhisperMessage').mockReturnValue({
      ephemeralKey: remoteEph,
      counter: 0,
      previousCounter: 0,
      ciphertext: new Uint8Array(48),
    })
    await expect((noOpenCipher as never as { doDecryptWhisperMessage: (d: Uint8Array, s: SessionEntry) => Promise<Uint8Array> })
      .doDecryptWhisperMessage(new Uint8Array([0x33, 1, 0, 0, 0, 0, 0, 0, 0, 0]), sendingSession))
      .rejects.toBeInstanceOf(SessionStateError)
  })

  it('covers enforceMessageKeyBudget special branches and deriveSecrets chunk guard', () => {
    const cipher = new SessionCipher(makeStorage(), new ProtocolAddress('peer', 1))

    let oddSize = 2501
    const weirdKeys = {
      get size() { return oddSize },
      keys() {
        return {
          next: () => ({ value: undefined, done: true }),
          [Symbol.iterator]() { return this },
        }
      },
      delete: () => {
        oddSize = 0
        return true
      },
    }

    let firstDelete = true
    const makeGlobalBag = (counter: number) => ({
      size: 1700,
      keys() {
        return {
          yielded: false,
          next(this: { yielded: boolean }) {
            if (this.yielded) return { value: undefined, done: true }
            this.yielded = true
            return { value: counter, done: false }
          },
          [Symbol.iterator]() { return this },
        }
      },
      delete: (_value: number) => {
        if (firstDelete) {
          firstDelete = false
          return false
        }
        return true
      },
    })

    const fakeSession = {
      chains: function* () {
        yield [new Uint8Array([1]), { messageKeys: weirdKeys }]
        yield [new Uint8Array([2]), { messageKeys: makeGlobalBag(2) }]
        yield [new Uint8Array([3]), { messageKeys: makeGlobalBag(3) }]
        yield [new Uint8Array([4]), { messageKeys: makeGlobalBag(4) }]
        yield [new Uint8Array([5]), { messageKeys: makeGlobalBag(5) }]
        yield [new Uint8Array([6]), { messageKeys: makeGlobalBag(6) }]
      }
    }

    ;(cipher as never as { enforceMessageKeyBudget: (session: unknown) => void }).enforceMessageKeyBudget(fakeSession)

    // Real map trimming path (oldest key eviction in overfull single chain).
    const realMap = new Map<number, Uint8Array>()
    for (let i = 0; i <= 2000; i++) {
      realMap.set(i, new Uint8Array([i & 0xff]))
    }
    const realChainSession = {
      chains: function* () {
        yield [new Uint8Array([9]), { messageKeys: realMap }]
      }
    }
    ;(cipher as never as { enforceMessageKeyBudget: (session: unknown) => void }).enforceMessageKeyBudget(realChainSession)
    expect(realMap.size).toBe(2000)

    const hkdfSpy = vi.spyOn(crypto, 'hkdf').mockImplementationOnce(() => ({
      length: 64,
      subarray: () => new Uint8Array(0),
    } as never))

    expect(() => (cipher as never as {
      deriveSecrets: (input: Uint8Array, salt: Uint8Array, info: Uint8Array, chunks: number) => Uint8Array[]
    }).deriveSecrets(new Uint8Array([1]), new Uint8Array(32), new Uint8Array([2]), 2))
      .toThrow('Invalid key derivation at chunk 0')

    hkdfSpy.mockRestore()
  })
})

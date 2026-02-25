import { describe, expect, it, vi } from 'vitest'
import { initCrypto, signalCrypto } from '../src/curve'
import {
  generateIdentityKeyPair,
  generatePreKey,
  generateRegistrationId,
  generateSignedPreKey,
} from '../src/key-helper'
import {
  generateIdentityKeyPairAsync,
  generatePreKeyAsync,
  generateRegistrationIdAsync,
  generateSignedPreKeyAsync,
} from '../src/key-helper-async'
import { FingerprintGenerator } from '../src/fingerprint'
import { ProtocolAddress } from '../src/protocol_address'
import {
  MessageCounterError,
  PreKeyError,
  SessionDecryptFailed,
  SessionError,
  SessionStateError,
  SignalError,
  UntrustedIdentityKeyError,
} from '../src/signal-errors'
import { ProtobufValidationError } from '../src/errors/protobuf-validation-error'
import { Deque } from '../src/internal/queue/deque'
import { getSignalLogger, setSignalLogger } from '../src/internal/logger'
import { assertUint8, fromBase64, toBase64, u8 } from '../src/session/utils'
import { runMigrations } from '../src/session/storage/migrations'
import { getMany, setMany, deleteMany } from '../src/session/storage/runtime'
import { createSessionStorage } from '../src/session/storage/adapter'
import { InMemoryStorage } from '../src/session/storage/in-memory'
import { SessionRecord } from '../src/session/record'
import { crypto } from '../src/crypto'
import { cryptoAsync } from '../src/crypto-async'
import { WhisperMessageEncoder } from '../src/session/cipher/encoding'
import * as rootIndex from '../src/index'
import * as sessionIndex from '../src/session'
import * as transportIndex from '../src/transport'

describe('curve + key helpers', () => {
  it('initializes libsodium and performs sign/verify + key conversions', async () => {
    await initCrypto()
    const id = await signalCrypto.generateIdentityKeyPair()
    const msg = new TextEncoder().encode('hello')
    const sig = signalCrypto.sign(id.privateKey, msg)

    expect(signalCrypto.verify(id.publicKey, msg, sig)).toBe(true)
    expect(signalCrypto.verify(id.publicKey, new Uint8Array([1, 2, 3]), sig)).toBe(false)

    const dh = await signalCrypto.generateDHKeyPair()
    const shared = signalCrypto.calculateAgreement(dh.publicKey, dh.privateKey)
    expect(shared).toBeInstanceOf(Uint8Array)

    expect(signalCrypto.convertIdentityPublicToX25519(id.publicKey)).toBeInstanceOf(Uint8Array)
    expect(signalCrypto.convertIdentityPrivateToX25519(id.privateKey)).toBeInstanceOf(Uint8Array)
  })

  it('validates argument lengths in curve helpers', async () => {
    await initCrypto()
    expect(() => signalCrypto.sign(new Uint8Array(10), new Uint8Array([1]))).toThrow('Ed25519 private key must be 64 bytes')
    expect(() => signalCrypto.verify(new Uint8Array(8), new Uint8Array([1]), new Uint8Array(64))).toThrow('Ed25519 public key must be 32 bytes')
    expect(() => signalCrypto.calculateAgreement(new Uint8Array(31), new Uint8Array(32))).toThrow('X25519 public key must be 32 bytes')
  })

  it('generates registration IDs and prekeys (sync + async)', async () => {
    await initCrypto()
    const id = await generateIdentityKeyPair()
    const signed = await generateSignedPreKey(id, 42)
    const pre = await generatePreKey(7)

    expect(signed.keyId).toBe(42)
    expect(pre.keyId).toBe(7)
    expect(generateRegistrationId()).toBeGreaterThanOrEqual(0)
    expect(generateRegistrationId()).toBeLessThanOrEqual(0x3fff)

    const idA = await generateIdentityKeyPairAsync()
    const signedA = await generateSignedPreKeyAsync(idA, 11)
    const preA = await generatePreKeyAsync(12)
    const regA = await generateRegistrationIdAsync()

    expect(signedA.signature.length).toBe(64)
    expect(preA.keyPair.publicKey.length).toBe(32)
    expect(regA).toBeGreaterThanOrEqual(0)
    expect(regA).toBeLessThanOrEqual(0x3fff)
  })

  it('rejects invalid key-helper inputs', async () => {
    await expect(generateSignedPreKey({ publicKey: new Uint8Array(32), privateKey: new Uint8Array(10) }, 1)).rejects.toThrow('Invalid Ed25519 private key')
    await expect(generateSignedPreKey({ publicKey: new Uint8Array(31), privateKey: new Uint8Array(64) }, 1)).rejects.toThrow('Invalid Ed25519 public key')
    await expect(generateSignedPreKey({ publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, -1)).rejects.toThrow('Invalid argument for signedKeyId')
    await expect(generatePreKey(-1)).rejects.toThrow('Invalid argument for keyId')
  })
})

describe('fingerprint + protocol address + error types', () => {
  it('builds deterministic fingerprints and validates arguments', () => {
    const g = new FingerprintGenerator(5)
    const left = g.createFor('alice', new Uint8Array(32).fill(1), 'bob', new Uint8Array(32).fill(2))
    const right = g.createFor('bob', new Uint8Array(32).fill(2), 'alice', new Uint8Array(32).fill(1))

    expect(left).toMatch(/^\d{60}$/)
    expect(left).toBe(right)
    expect(() => new FingerprintGenerator(0)).toThrow('iterations must be a positive integer')
    expect(() => g.createFor('alice', new Uint8Array(1), 1 as never, new Uint8Array(1))).toThrow('Identifiers must be strings')
    expect(() => g.createFor('alice', null as never, 'bob', new Uint8Array(1))).toThrow('Identity keys must be Uint8Array')
  })

  it('covers protocol address invalid encodings and equality', () => {
    expect(() => ProtocolAddress.from('')).toThrow('Invalid address encoding')
    expect(() => ProtocolAddress.from('alice.x')).toThrow('Invalid deviceId encoding')
    expect(() => new ProtocolAddress('a.b', 1)).toThrow('id must not contain')
    expect(() => new ProtocolAddress('alice', -1)).toThrow('deviceId must be a non-negative safe integer')

    const a = new ProtocolAddress('alice', 1)
    expect(a.equals({})).toBe(false)
    expect(a.toString()).toBe('alice.1')
  })

  it('instantiates full error hierarchy', () => {
    const cause = new Error('root')
    const signalErr = new SignalError('x', { cause })
    const untrusted = new UntrustedIdentityKeyError('alice', new Uint8Array([1]))

    expect(signalErr.name).toBe('SignalError')
    expect(untrusted.addr).toBe('alice')
    expect(untrusted.identityKey).toEqual(new Uint8Array([1]))
    expect(new SessionError('m')).toBeInstanceOf(SignalError)
    expect(new SessionStateError('m').code).toBe('SESSION_STATE_ERROR')
    expect(new SessionDecryptFailed('m').code).toBe('SESSION_DECRYPT_FAILED')
    expect(new MessageCounterError('m')).toBeInstanceOf(SessionError)
    expect(new PreKeyError('m')).toBeInstanceOf(SessionError)

    const protoErr = new ProtobufValidationError('bad')
    expect(protoErr.name).toBe('ProtobufValidationError')
  })
})

describe('storage/runtime/utils/logger/deque', () => {
  it('handles deque operations and compaction', () => {
    const d = new Deque<number>()
    expect(d.shift()).toBeUndefined()
    for (let i = 0; i < 2200; i++) d.push(i)
    d.spliceFront(1100)
    expect(d.length).toBe(1100)
    expect(d.at(0)).toBe(1100)
    expect(d.shift()).toBe(1100)
    d.spliceFront(99999)
    expect(d.length).toBe(0)
  })

  it('asserts uint8 and base64 helpers', () => {
    const bytes = new Uint8Array([1, 2, 3])
    const b64 = toBase64(bytes)
    expect(Array.from(fromBase64(b64))).toEqual([1, 2, 3])
    expect(u8.encode(bytes)).toBe(b64)
    expect(u8.decode(b64)).toEqual(bytes)
    expect(u8.encode(undefined)).toBeUndefined()
    expect(u8.decode(undefined)).toBeUndefined()
    expect(() => assertUint8('x')).toThrow('Expected Uint8Array instead of: string')
  })

  it('supports optional logger set/get', () => {
    const logger = { debug: vi.fn(), warn: vi.fn() }
    setSignalLogger(logger)
    expect(getSignalLogger()).toBe(logger)
    setSignalLogger(undefined)
    expect(getSignalLogger()).toBeUndefined()
  })

  it('runtime helpers support sync and async fallbacks', async () => {
    const syncMap = new Map<string, number>()
    const syncAdapter = {
      get: (k: string) => syncMap.get(k),
      set: (k: string, v: number) => void syncMap.set(k, v),
      delete: (k: string) => void syncMap.delete(k),
    }

    setMany(syncAdapter, [{ key: 'a', value: 1 }, { key: 'b', value: 2 }])
    expect(getMany(syncAdapter, ['a', 'x'])).toEqual([1, undefined])
    deleteMany(syncAdapter, [{ key: 'a' }])
    expect(syncMap.has('a')).toBe(false)

    const asyncMap = new Map<string, number>()
    const asyncAdapter = {
      get: async (k: string) => asyncMap.get(k),
      set: async (k: string, v: number) => void asyncMap.set(k, v),
      delete: async (k: string) => void asyncMap.delete(k),
    }

    await setMany(asyncAdapter, [{ key: 'k', value: 9 }])
    await expect(getMany(asyncAdapter, ['k'])).resolves.toEqual([9])
    await deleteMany(asyncAdapter, [{ key: 'k' }])
  })

  it('session storage adapter handles bootstrap, identity trust and migrations', async () => {
    const adapter = new InMemoryStorage<unknown>()
    const store = createSessionStorage(adapter)

    await expect(store.getOurIdentity()).rejects.toThrow('Our identity not found in storage')
    await expect(store.getOurRegistrationId()).rejects.toThrow('registration id missing')

    const identity = { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) }
    await store.storeBootstrap(identity, 999)
    expect((await store.getOurIdentity()).pubKey.length).toBe(32)
    expect(await store.getOurRegistrationId()).toBe(999)

    const trusted = await store.isTrustedIdentity('bob', new Uint8Array([1, 2, 3]))
    const notTrusted = await store.isTrustedIdentity('bob', new Uint8Array([9, 9, 9]))
    expect(trusted).toBe(true)
    expect(notTrusted).toBe(false)

    const record = new SessionRecord()
    await store.storeSession('bob.1', record)
    expect(await store.loadSession('bob.1')).toBeInstanceOf(SessionRecord)

    await store.migrateLegacyIdentityStorage('legacy', new Uint8Array([7]))
    expect(await store.isTrustedIdentity('legacy', new Uint8Array([7]))).toBe(true)

    await store.storeSessionAndRemovePreKey('bob.1', record, 88)
    await store.removePreKey(88)
    await store.primeSession('bob.1')

    await runMigrations(adapter, 1, 2)
  })
})

describe('crypto async + encoding + barrel modules', () => {
  it('encrypt/decrypt async API + invalid argument guards', async () => {
    const key = new Uint8Array(32).fill(1)
    const plain = new TextEncoder().encode('secret')
    const data = await cryptoAsync.encrypt(key, plain, { iv: new Uint8Array(12).fill(2) })
    const out = await cryptoAsync.decrypt(key, data)

    expect(new TextDecoder().decode(out)).toBe('secret')
    await expect(cryptoAsync.encrypt(new Uint8Array(2), plain)).rejects.toThrow('Key must be 32 bytes')
    await expect(cryptoAsync.decrypt(key, { ...data, tag: new Uint8Array(2) })).rejects.toThrow('Tag must be 16 bytes for AES-GCM')
    await expect(cryptoAsync.hkdf(new Uint8Array(), new Uint8Array([1]), new Uint8Array([1]), { length: 1 })).rejects.toThrow('IKM cannot be empty')
  })

  it('encodes/decodes whisper and prekey messages', () => {
    const whisper = {
      ephemeralKey: new Uint8Array([1]),
      counter: 1,
      previousCounter: 0,
      ciphertext: crypto.sha512(new Uint8Array([1])).subarray(0, 16),
    }
    const encoded = WhisperMessageEncoder.encodeWhisperMessage(whisper)
    expect(WhisperMessageEncoder.decodeWhisperMessage(encoded).counter).toBe(1)

    const prekey = {
      identityKey: new Uint8Array([1]),
      registrationId: 2,
      baseKey: new Uint8Array([3]),
      signedPreKeyId: 4,
      preKeyId: 5,
      message: encoded,
    }
    const encodedPre = WhisperMessageEncoder.encodePreKeyWhisperMessage(prekey)
    expect(WhisperMessageEncoder.decodePreKeyWhisperMessage(encodedPre).signedPreKeyId).toBe(4)
  })

  it('loads barrel modules', () => {
    expect(rootIndex).toBeDefined()
    expect(sessionIndex).toBeDefined()
    expect(transportIndex.WhisperMessageEncoder).toBeTypeOf('function')
  })
})

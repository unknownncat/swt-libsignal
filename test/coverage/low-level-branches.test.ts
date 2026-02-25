import { afterEach, describe, expect, it, vi } from 'vitest'
import { crypto } from '../../src/crypto'
import { FingerprintGenerator } from '../../src/fingerprint'
import { ProtocolAddress } from '../../src/protocol_address'
import { SignalError } from '../../src/signal-errors'
import { assertUint8, toBase64, u8 } from '../../src/session/utils'
import { asAesKey32, asEd25519PublicKey, asMacKey32 } from '../../src/types/branded'
import { secureZero } from '../../src/utils/secure-zero'

afterEach(() => {
  vi.restoreAllMocks()
  vi.doUnmock('crypto')
  vi.doUnmock('node:crypto')
  vi.resetModules()
})

describe('coverage - low level guards', () => {
  it('covers crypto sync argument guards', () => {
    const key = new Uint8Array(32).fill(1)
    const plaintext = new Uint8Array([1, 2, 3])

    expect(() => crypto.encrypt(new Uint8Array(1), plaintext)).toThrow('Key must be 32 bytes')
    expect(() => crypto.encrypt(key, plaintext, { iv: new Uint8Array(1) })).toThrow('IV must be 12 bytes for AES-GCM')

    const sample = crypto.encrypt(key, plaintext, { iv: new Uint8Array(12).fill(2), aad: new Uint8Array([7]) })
    expect(() => crypto.decrypt(new Uint8Array(1), sample)).toThrow('Key must be 32 bytes')
    expect(() => crypto.decrypt(key, { ...sample, iv: new Uint8Array(1) })).toThrow('IV must be 12 bytes for AES-GCM')
    expect(() => crypto.decrypt(key, { ...sample, tag: new Uint8Array(1) })).toThrow('Tag must be 16 bytes for AES-GCM')

    expect(() => crypto.hkdf(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), { length: 0 })).toThrow('length must be positive integer')
    expect(() => crypto.hkdf(new Uint8Array(), new Uint8Array([2]), new Uint8Array([3]), { length: 32 })).toThrow('IKM cannot be empty')
    expect(() => crypto.hkdf(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), { length: 255 * 32 + 1 })).toThrow('HKDF length must be <=')

    const bufferKey = Buffer.alloc(32, 3) as unknown as Uint8Array
    const bufferIv = Buffer.alloc(12, 4) as unknown as Uint8Array
    const bufferMsg = Buffer.from([9, 8, 7]) as unknown as Uint8Array
    const encryptedFromBuffers = crypto.encrypt(bufferKey, bufferMsg, { iv: bufferIv, aad: Buffer.from([1, 2]) as unknown as Uint8Array })
    const decryptedFromBuffers = crypto.decrypt(bufferKey, encryptedFromBuffers, { aad: Buffer.from([1, 2]) as unknown as Uint8Array })
    expect(decryptedFromBuffers).toEqual(new Uint8Array([9, 8, 7]))

    const encryptedNoAad = crypto.encrypt(new Uint8Array(32).fill(9), new Uint8Array([4, 5, 6]), { iv: new Uint8Array(12).fill(7) })
    const decryptedNoAad = crypto.decrypt(new Uint8Array(32).fill(9), encryptedNoAad)
    expect(decryptedNoAad).toEqual(new Uint8Array([4, 5, 6]))
  })

  it('covers crypto async guards', async () => {
    const asyncCrypto = await import('../../src/crypto-async')
    const key = new Uint8Array(32).fill(1)

    await expect(asyncCrypto.encryptAsync(new Uint8Array(1), new Uint8Array([1]))).rejects.toThrow('Key must be 32 bytes')
    await expect(asyncCrypto.encryptAsync(key, new Uint8Array([1]), { iv: new Uint8Array(1) })).rejects.toThrow('IV must be 12 bytes for AES-GCM')

    await expect(asyncCrypto.decryptAsync(new Uint8Array(1), {
      ciphertext: new Uint8Array([1]),
      iv: new Uint8Array(12).fill(2),
      tag: new Uint8Array(16).fill(3),
    })).rejects.toThrow('Key must be 32 bytes')

    await expect(asyncCrypto.decryptAsync(key, {
      ciphertext: new Uint8Array([1]),
      iv: new Uint8Array(1),
      tag: new Uint8Array(16),
    })).rejects.toThrow('IV must be 12 bytes for AES-GCM')

    await expect(asyncCrypto.decryptAsync(key, {
      ciphertext: new Uint8Array([1]),
      iv: new Uint8Array(12),
      tag: new Uint8Array(1),
    })).rejects.toThrow('Tag must be 16 bytes for AES-GCM')

    await expect(asyncCrypto.hkdfAsync(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), { length: 0 })).rejects.toThrow('length must be positive integer')
    await expect(asyncCrypto.hkdfAsync(new Uint8Array(), new Uint8Array([2]), new Uint8Array([3]), { length: 32 })).rejects.toThrow('IKM cannot be empty')
    await expect(asyncCrypto.hkdfAsync(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), { length: 255 * 32 + 1 })).rejects.toThrow('HKDF length must be <=')
  })

  it('covers crypto async RNG error branch', async () => {
    vi.doMock('node:crypto', async () => {
      const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto')
      return {
        ...actual,
        randomBytes: ((size: number, cb?: (error: Error | null, buffer: Buffer) => void) => {
          if (cb) {
            cb(new Error('rng fail'), Buffer.alloc(0))
            return undefined
          }
          return Buffer.alloc(size)
        }) as typeof actual.randomBytes,
      }
    })

    const asyncCrypto = await import('../../src/crypto-async')
    await expect(asyncCrypto.encryptAsync(new Uint8Array(32).fill(1), new Uint8Array([1]))).rejects.toThrow('rng fail')
  })

  it('covers curve not-ready and signature-length guards', async () => {
    const curve = await import('../../src/curve')
    expect(() => curve.signalCrypto.sign(new Uint8Array(64), new Uint8Array([1]))).toThrow('libsodium is not initialized')

    await curve.initCrypto()
    expect(() => curve.signalCrypto.verify(new Uint8Array(32), new Uint8Array([1]), new Uint8Array(1))).toThrow('Signature must be 64 bytes')
  })

  it('covers fingerprint key-length and short-hash failure', () => {
    const g = new FingerprintGenerator(1)
    expect(() => g.createFor('alice', new Uint8Array(31), 'bob', new Uint8Array(32))).toThrow('Identity key must be 32 bytes')

    const spy = vi.spyOn(crypto, 'sha512').mockReturnValue(new Uint8Array(4))
    expect(() => g.createFor('alice', new Uint8Array(32), 'bob', new Uint8Array(32))).toThrow('Hash output too small')
    spy.mockRestore()
  })

  it('covers protocol address factory and constructor edge guards', () => {
    expect(() => ProtocolAddress.from(123 as unknown as string)).toThrow('encodedAddress must be a string')
    expect(() => ProtocolAddress.from(`alice.${Number.MAX_SAFE_INTEGER + 1}`)).toThrow('Invalid deviceId value')
    expect(() => new ProtocolAddress('', 0)).toThrow('id must be a non-empty string')
  })

  it('covers key-helper registration fallback and async RNG errors', async () => {
    vi.doMock('crypto', async () => {
      const actual = await vi.importActual<typeof import('crypto')>('crypto')
      return {
        ...actual,
        randomBytes: (() => Buffer.alloc(0)) as typeof actual.randomBytes,
      }
    })

    const keyHelper = await import('../../src/key-helper')
    expect(keyHelper.generateRegistrationId()).toBe(0)

    vi.doUnmock('node:crypto')
    vi.resetModules()

    vi.doMock('node:crypto', async () => {
      const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto')
      return {
        ...actual,
        randomBytes: ((size: number, cb?: (error: Error | null, buffer: Buffer) => void) => {
          if (cb) {
            cb(new Error('rng async fail'), Buffer.alloc(0))
            return undefined
          }
          return Buffer.alloc(size)
        }) as typeof actual.randomBytes,
      }
    })

    const keyHelperAsync = await import('../../src/key-helper-async')
    await expect(keyHelperAsync.generateRegistrationIdAsync()).rejects.toThrow('rng async fail')

    vi.doUnmock('node:crypto')
    vi.resetModules()

    vi.doMock('node:crypto', async () => {
      const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto')
      return {
        ...actual,
        randomBytes: ((size: number, cb?: (error: Error | null, buffer: Buffer) => void) => {
          if (cb) {
            cb(null, Buffer.alloc(0))
            return undefined
          }
          return Buffer.alloc(size)
        }) as typeof actual.randomBytes,
      }
    })

    const keyHelperAsyncFallback = await import('../../src/key-helper-async')
    await expect(keyHelperAsyncFallback.generateRegistrationIdAsync()).resolves.toBe(0)
  })

  it('covers session utils object-name path and Buffer base64 path', () => {
    expect(() => assertUint8({})).toThrow('Expected Uint8Array')
    expect(() => assertUint8(Object.create(null))).toThrow('Expected Uint8Array')
    expect(() => assertUint8(null)).toThrow('Expected Uint8Array')
    expect(() => assertUint8({ constructor: {} })).toThrow('Expected Uint8Array')

    const b64 = toBase64(Buffer.from([1, 2, 3]) as unknown as Uint8Array)
    expect(b64).toBe(Buffer.from([1, 2, 3]).toString('base64'))

    expect(u8.encode(new Uint8Array([1]))).toBeTypeOf('string')
    expect(u8.encode(undefined)).toBeUndefined()
    expect(u8.decode('AQ==')).toEqual(new Uint8Array([1]))
    expect(u8.decode(undefined)).toBeUndefined()
  })

  it('covers SignalError when captureStackTrace is unavailable', () => {
    const original = Error.captureStackTrace
    ;(Error as ErrorConstructor & { captureStackTrace?: typeof Error.captureStackTrace }).captureStackTrace = undefined
    try {
      const err = new SignalError('x')
      expect(err.name).toBe('SignalError')
    } finally {
      ;(Error as ErrorConstructor & { captureStackTrace?: typeof Error.captureStackTrace }).captureStackTrace = original
    }
  })

  it('covers branded helpers including AES/MAC aliases and invalid input type', () => {
    expect(asAesKey32(new Uint8Array(32))).toBeInstanceOf(Uint8Array)
    expect(asMacKey32(new Uint8Array(32))).toBeInstanceOf(Uint8Array)
    expect(() => asEd25519PublicKey('x' as unknown as Uint8Array)).toThrow('must be Uint8Array')
  })

  it('covers secureZero with empty input', () => {
    expect(() => secureZero(undefined)).not.toThrow()
    expect(() => secureZero(null)).not.toThrow()
  })
})

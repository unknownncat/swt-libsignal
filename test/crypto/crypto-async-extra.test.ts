import { describe, expect, it, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { cryptoAsync, encryptAsync, hkdfAsync, hmacSha256Async, sha512Async } from '../../src/crypto-async'

describe('crypto-async extra branches', () => {
  it('covers random iv generation and digest/mac helpers', async () => {
    const key = new Uint8Array(32).fill(3)
    const plaintext = new Uint8Array([1, 2, 3, 4])

    const encrypted = await encryptAsync(key, plaintext)
    expect(encrypted.iv.length).toBe(12)

    const digest = await sha512Async(plaintext)
    const mac = await hmacSha256Async(key, plaintext)
    expect(digest.length).toBe(64)
    expect(mac.length).toBe(32)

    await expect(hkdfAsync(new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3]), { length: 255 * 32 + 1 }))
      .rejects.toThrow('HKDF length must be <= 8160')
  })

  it('throws when encrypted payload cannot be split into ciphertext/tag', async () => {
    const key = new Uint8Array(32).fill(7)
    const subtleEncrypt = vi.spyOn(webcrypto.subtle, 'encrypt')
    subtleEncrypt.mockResolvedValueOnce(new Uint8Array([1, 2, 3]).buffer)

    await expect(cryptoAsync.encrypt(key, new Uint8Array([9]))).rejects.toThrow('Ciphertext payload must include a 16-byte tag')
    subtleEncrypt.mockRestore()
  })
})

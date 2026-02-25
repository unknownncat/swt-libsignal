import { describe, expect, it } from 'vitest'
import { createSignalAsync, createSignalSync } from '../src/public/dual-api'
import { crypto } from '../src/crypto'

const key = new Uint8Array(32).fill(11)
const iv = new Uint8Array(12).fill(22)
const aad = new Uint8Array([1, 2, 3])
const plaintext = new TextEncoder().encode('deterministic-message')

describe('crypto APIs', () => {
  it('sync encrypt/decrypt round-trip works', () => {
    const encrypted = crypto.encrypt(key, plaintext, { iv, aad })
    const decrypted = crypto.decrypt(key, encrypted, { aad })
    expect(new TextDecoder().decode(decrypted)).toBe('deterministic-message')
  })

  it('sync and async APIs return equivalent results for deterministic inputs', async () => {
    const syncApi = createSignalSync()
    const asyncApi = await createSignalAsync({ workers: 1 })

    try {
      const syncEncrypted = syncApi.encrypt(key, plaintext, { iv, aad })
      const asyncEncrypted = await asyncApi.encrypt(key, plaintext, { iv, aad })

      expect(Array.from(asyncEncrypted.ciphertext)).toEqual(Array.from(syncEncrypted.ciphertext))
      expect(Array.from(asyncEncrypted.tag)).toEqual(Array.from(syncEncrypted.tag))

      const syncHash = syncApi.sha512(plaintext)
      const asyncHash = await asyncApi.sha512(plaintext)
      expect(Array.from(asyncHash)).toEqual(Array.from(syncHash))

      const syncHkdf = syncApi.hkdf(plaintext, key, aad, { length: 42 })
      const asyncHkdf = await asyncApi.hkdf(plaintext, key, aad, { length: 42 })
      expect(Array.from(asyncHkdf)).toEqual(Array.from(syncHkdf))
    } finally {
      await asyncApi.close()
    }
  })
})

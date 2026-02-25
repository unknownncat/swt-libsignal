import { createSignalAsync, createSignalSync, crypto, cryptoAsync } from '../../src/public'

export interface CryptoRuntimeCheckResult {
  readonly syncRoundTrip: boolean
  readonly asyncRoundTrip: boolean
  readonly dualRoundTrip: boolean
  readonly hkdfLength: number
  readonly digestLength: number
}

export async function runCryptoRuntimeCheck(): Promise<CryptoRuntimeCheckResult> {
  const key = new Uint8Array(32).fill(7)
  const iv = new Uint8Array(12).fill(9)
  const aad = new TextEncoder().encode('docs-crypto-runtime')
  const plaintext = new TextEncoder().encode('crypto-runtime-check')

  const sealedSync = crypto.encrypt(key, plaintext, { iv, aad })
  const openedSync = crypto.decrypt(key, sealedSync, { aad })

  const sealedAsync = await cryptoAsync.encrypt(key, plaintext, { iv, aad })
  const openedAsync = await cryptoAsync.decrypt(key, sealedAsync, { aad })

  const syncApi = createSignalSync()
  const asyncApi = await createSignalAsync({ workers: 1, maxPendingJobs: 16 })
  try {
    const sealedDual = syncApi.encrypt(key, plaintext, { iv, aad })
    const openedDual = await asyncApi.decrypt(key, sealedDual, { aad })
    const hkdf = crypto.hkdf(key, new Uint8Array(32), new TextEncoder().encode('docs-hkdf'), { length: 64 })
    const digest = await cryptoAsync.sha512(plaintext)

    return {
      syncRoundTrip: Buffer.from(openedSync).equals(Buffer.from(plaintext)),
      asyncRoundTrip: Buffer.from(openedAsync).equals(Buffer.from(plaintext)),
      dualRoundTrip: Buffer.from(openedDual).equals(Buffer.from(plaintext)),
      hkdfLength: hkdf.length,
      digestLength: digest.length,
    }
  } finally {
    await asyncApi.close()
  }
}

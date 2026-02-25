import { describe, expect, it } from 'vitest'
import { createSignalAsync } from '../../src/public/dual-api'

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('dual api worker hardening', () => {
  it('smoke-tests encrypt/decrypt through module worker', async () => {
    const api = await createSignalAsync({ workers: 1, maxPendingJobs: 8 })
    try {
      const key = new Uint8Array(32).fill(11)
      const plaintext = new TextEncoder().encode('worker-smoke')
      const encrypted = await api.encrypt(key, plaintext, { iv: new Uint8Array(12).fill(12) })
      const decrypted = await api.decrypt(key, encrypted)
      expect(decrypted).toEqual(plaintext)
    } finally {
      await api.close()
    }
  })

  it('rejects pending job on worker crash and recovers with a new worker', async () => {
    const api = await createSignalAsync({ workers: 1, maxPendingJobs: 8 })
    try {
      await expect(api.__terminateWorkerForTest?.(0)).rejects.toThrow('async worker crashed while processing jobs')

      let recovered: Uint8Array | undefined
      for (let i = 0; i < 5; i++) {
        try {
          recovered = await api.sha512(new Uint8Array([4, 5, 6]))
          break
        } catch {
          await wait(25)
        }
      }

      expect(recovered).toBeInstanceOf(Uint8Array)
    } finally {
      await api.close()
    }
  })
})

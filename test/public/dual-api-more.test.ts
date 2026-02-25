import { describe, expect, it } from 'vitest'
import { createSignalAsync, createSignalSync } from '../../src/public/dual-api'

describe('dual api extra coverage', () => {
  it('validates createSignalAsync options', async () => {
    await expect(createSignalAsync({ workers: 0 })).rejects.toThrow('workers must be a positive integer')
    await expect(createSignalAsync({ workers: 1, maxPendingJobs: 0 })).rejects.toThrow('maxPendingJobs must be a positive integer')
  })

  it('supports worker info + close and sync surface', async () => {
    const sync = createSignalSync()
    expect(sync.encrypt).toBeTypeOf('function')

    const api = await createSignalAsync({ workers: 1, maxPendingJobs: 1 })
    try {
      const info = await api.getWorkerInfo()
      expect(info.isMainThread).toBe(false)
      expect(info.threadId).toBeGreaterThan(0)

      const key = new Uint8Array(32).fill(1)
      const msg = new Uint8Array([1, 2, 3])
      const iv = new Uint8Array(12).fill(2)
      const [first, second] = await Promise.allSettled([
        api.encrypt(key, msg, { iv }),
        api.encrypt(key, msg, { iv }),
      ])

      const errors = [first, second].filter((x): x is PromiseRejectedResult => x.status === 'rejected')
      expect(errors.length).toBe(1)
      expect(String(errors[0].reason)).toContain('async worker backpressure: too many pending jobs')
    } finally {
      await api.close()
    }
  })
})

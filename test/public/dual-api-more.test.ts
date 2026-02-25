import { describe, expect, it } from 'vitest'
import { createSignalAsync, createSignalSync } from '../../src/public/dual-api'

describe('dual api extra coverage', () => {
  it('validates createSignalAsync options', async () => {
    await expect(createSignalAsync({ workers: 0 })).rejects.toThrow('workers must be a positive integer')
    await expect(createSignalAsync({ workers: 1, maxPendingJobs: 0 })).rejects.toThrow('maxPendingJobs must be a positive integer')
    await expect(createSignalAsync({ workers: 1, maxQueuedJobs: 0 })).rejects.toThrow('maxQueuedJobs must be a positive integer')
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

  it('queues requests on backpressure when enabled', async () => {
    const api = await createSignalAsync({
      workers: 1,
      maxPendingJobs: 1,
      queueOnBackpressure: true,
      maxQueuedJobs: 4,
    })

    try {
      const key = new Uint8Array(32).fill(4)
      const msg = new Uint8Array(1024 * 1024).fill(9)

      const results = await Promise.all([
        api.encrypt(key, msg, { iv: new Uint8Array(12).fill(1) }),
        api.encrypt(key, msg, { iv: new Uint8Array(12).fill(2) }),
        api.encrypt(key, msg, { iv: new Uint8Array(12).fill(3) }),
      ])

      expect(results).toHaveLength(3)
      expect(results[0].ciphertext.length).toBeGreaterThan(0)
      expect(results[1].ciphertext.length).toBeGreaterThan(0)
      expect(results[2].ciphertext.length).toBeGreaterThan(0)
    } finally {
      await api.close()
    }
  })

  it('fails fast when backpressure queue is full', async () => {
    const api = await createSignalAsync({
      workers: 1,
      maxPendingJobs: 1,
      queueOnBackpressure: true,
      maxQueuedJobs: 1,
    })

    try {
      const key = new Uint8Array(32).fill(5)
      const msg = new Uint8Array(1024 * 1024).fill(8)
      const jobs = Array.from({ length: 8 }, (_, idx) =>
        api.encrypt(key, msg, { iv: new Uint8Array(12).fill((idx % 200) + 10) }),
      )

      const settled = await Promise.allSettled(jobs)
      const rejected = settled.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
      expect(rejected.length).toBeGreaterThan(0)
      expect(String(rejected[0].reason)).toContain('async worker backpressure queue full')
    } finally {
      await api.close()
    }
  })
})

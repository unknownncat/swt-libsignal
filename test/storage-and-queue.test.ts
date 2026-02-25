import { describe, expect, it } from 'vitest'
import { enqueue, flushQueue } from '../src/job_queue'
import { InMemoryStorage } from '../src/session/storage/in-memory'

describe('InMemoryStorage', () => {
  it('isolates Uint8Array values by default', () => {
    const store = new InMemoryStorage<Uint8Array>()
    const value = new Uint8Array([1, 2, 3])
    store.set('k', value)

    value[0] = 9
    const stored = store.get('k')
    expect(stored).toBeDefined()
    expect(Array.from(stored ?? [])).toEqual([1, 2, 3])

    stored?.fill(7)
    expect(Array.from(store.get('k') ?? [])).toEqual([1, 2, 3])
  })

  it('zeroize and clear(secure) overwrite sensitive bytes', () => {
    const store = new InMemoryStorage<Uint8Array>()
    store.set('a', new Uint8Array([9, 9]))
    store.zeroize('a')
    expect(Array.from(store.get('a') ?? [])).toEqual([0, 0])

    store.set('b', new Uint8Array([1, 1]))
    store.clear({ secure: true })
    expect(store.get('a')).toBeUndefined()
    expect(store.get('b')).toBeUndefined()
  })
})

describe('job queue', () => {
  it('runs jobs serially inside the same bucket', async () => {
    const order: string[] = []

    const first = enqueue('bucket', async () => {
      order.push('start-1')
      await new Promise((resolve) => setTimeout(resolve, 15))
      order.push('end-1')
      return 1
    })

    const second = enqueue('bucket', async () => {
      order.push('start-2')
      order.push('end-2')
      return 2
    })

    const [a, b] = await Promise.all([first, second])
    expect(a).toBe(1)
    expect(b).toBe(2)
    expect(order).toEqual(['start-1', 'end-1', 'start-2', 'end-2'])

    await flushQueue('bucket')
  })

  it('aborts jobs when timeout is exceeded', async () => {
    await expect(
      enqueue(
        'timeout',
        async (signal) => {
          await new Promise<void>((_, reject) => {
            const timer = setTimeout(() => reject(new Error('job did not abort in time')), 40)
            signal.addEventListener('abort', () => {
              clearTimeout(timer)
              reject(signal.reason as Error)
            }, { once: true })
          })
          return 'ok'
        },
        { timeoutMs: 5 },
      ),
    ).rejects.toThrow('queue job timeout after 5ms')
  })
})

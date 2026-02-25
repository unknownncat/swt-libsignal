import { EventEmitter } from 'node:events'
import { afterEach, describe, expect, it, vi } from 'vitest'

type FakeMode = 'ok' | 'error' | 'silent'

class FakeWorker extends EventEmitter {
  static instances: FakeWorker[] = []
  static modes: FakeMode[] = []
  static throwOnConstruct = false
  static disableRemoveAll = false
  static emitExitOnTerminate = true

  readonly threadId: number

  constructor(_url: URL) {
    super()
    if (FakeWorker.throwOnConstruct) {
      throw new Error('worker construct failed')
    }
    this.threadId = FakeWorker.instances.length + 1
    FakeWorker.instances.push(this)
  }

  static reset(): void {
    FakeWorker.instances = []
    FakeWorker.modes = []
    FakeWorker.throwOnConstruct = false
    FakeWorker.disableRemoveAll = false
    FakeWorker.emitExitOnTerminate = true
  }

  override removeAllListeners(eventName?: string | symbol): this {
    if (FakeWorker.disableRemoveAll) return this
    return super.removeAllListeners(eventName)
  }

  postMessage(payload: {
    id: number
    request: { type: string }
  }): void {
    const mode = FakeWorker.modes.shift() ?? 'ok'
    if (mode === 'silent') return
    if (mode === 'error') {
      this.emit('message', {
        id: payload.id,
        response: { ok: false, message: 'worker failure' },
      })
      return
    }

    const type = payload.request.type
    const value = type === 'encrypt'
      ? { ciphertext: new Uint8Array([1]), iv: new Uint8Array(12), tag: new Uint8Array(16) }
      : type === 'decrypt'
        ? new Uint8Array([2])
        : type === 'threadInfo'
          ? { threadId: this.threadId, isMainThread: false }
          : new Uint8Array([3])

    this.emit('message', {
      id: payload.id,
      response: { ok: true, type, value },
    })
  }

  terminate(): Promise<number> {
    if (FakeWorker.emitExitOnTerminate) {
      this.emit('exit', 0)
    }
    return Promise.resolve(0)
  }
}

async function loadDualApi() {
  FakeWorker.reset()
  vi.doMock('node:worker_threads', () => ({ Worker: FakeWorker }))
  vi.resetModules()
  return await import('../../src/public/dual-api')
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.doUnmock('node:worker_threads')
  vi.resetModules()
  FakeWorker.reset()
})

describe('coverage - dual api branches', () => {
  it('covers default options, stale message, error response, out-of-range terminate and closed run', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync()
    const worker = FakeWorker.instances[0]!

    // message for unknown id => !job branch
    worker.emit('message', {
      id: 99999,
      response: { ok: true, type: 'sha512', value: new Uint8Array([1]) },
    })

    FakeWorker.modes.push('error')
    await expect(api.encrypt(new Uint8Array(32), new Uint8Array([1]), { iv: new Uint8Array(12) }))
      .rejects.toThrow('worker failure')
    await expect(api.encrypt(new Uint8Array(32), new Uint8Array([2]))).resolves.toEqual({
      ciphertext: new Uint8Array([1]),
      iv: new Uint8Array(12),
      tag: new Uint8Array(16),
    })

    await expect(api.hmacSha256(new Uint8Array(32), new Uint8Array([5]))).resolves.toEqual(new Uint8Array([3]))
    await expect(api.__terminateWorkerForTest?.(99)).rejects.toThrow('worker index out of range')

    await api.close()
    worker.emit('error', new Error('late-error-after-close'))

    await expect(api.sha512(new Uint8Array([1]))).rejects.toThrow('async worker pool is closed')
  })

  it('covers selectWorker skip for dead worker after failed revive construction', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync({ workers: 1, maxPendingJobs: 1 })
    const worker = FakeWorker.instances[0]!

    FakeWorker.throwOnConstruct = true
    expect(() => worker.emit('error', new Error('force-revive-fail'))).toThrow('worker construct failed')
    FakeWorker.throwOnConstruct = false

    await expect(api.sha512(new Uint8Array([1]))).rejects.toThrow('async worker backpressure: too many pending jobs')
    await api.close()
  })

  it('covers drainBuffered branch when buffered shift returns undefined', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync({
      workers: 1,
      maxPendingJobs: 1,
      queueOnBackpressure: true,
      maxQueuedJobs: 2,
    })
    const worker = FakeWorker.instances[0]!

    FakeWorker.modes.push('silent')
    const first = api.sha512(new Uint8Array([1]))
    const second = api.sha512(new Uint8Array([2]))

    const realShift = Array.prototype.shift
    let shiftedOnce = false
    Array.prototype.shift = function (this: unknown[]) {
      if (!shiftedOnce && this.length > 0) {
        const candidate = this[0] as Record<string, unknown> | undefined
        if (candidate && 'request' in candidate) {
          shiftedOnce = true
          return undefined
        }
      }
      return realShift.call(this)
    }

    try {
      worker.emit('message', {
        id: 1,
        response: { ok: true, type: 'sha512', value: new Uint8Array([9]) },
      })

      await expect(first).resolves.toEqual(new Uint8Array([9]))
      await api.close()
      await expect(second).rejects.toThrow('async worker pool is closed')
    } finally {
      Array.prototype.shift = realShift
    }
  })

  it('covers drainBuffered closed short-circuit during message handling', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync({
      workers: 1,
      maxPendingJobs: 1,
      queueOnBackpressure: true,
      maxQueuedJobs: 1,
    })
    const worker = FakeWorker.instances[0]!

    FakeWorker.modes.push('silent')
    const first = api.sha512(new Uint8Array([1]))
    const second = api.sha512(new Uint8Array([2]))

    const response = {
      get ok() {
        void api.close()
        return false
      },
      message: 'forced failure',
    }

    worker.emit('message', { id: 1, response })

    await expect(first).rejects.toThrow('forced failure')
    await expect(second).rejects.toThrow('async worker pool is closed')
  })

  it('covers worker-specific rejection iteration in crash handling', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync({
      workers: 2,
      maxPendingJobs: 2,
      queueOnBackpressure: false,
    })

    FakeWorker.modes.push('silent', 'silent')
    const one = api.sha512(new Uint8Array([1]))
    const two = api.sha512(new Uint8Array([2]))

    await expect(api.__terminateWorkerForTest?.(0)).rejects.toThrow('async worker crashed while processing jobs')
    await api.close()

    await expect(one).rejects.toThrow('async worker crashed while processing jobs')
    await expect(two).rejects.toThrow('async worker pool is closed')
  })

  it('covers close() rejection branches for pending and buffered requests', async () => {
    const { createSignalAsync } = await loadDualApi()
    const api = await createSignalAsync({
      workers: 1,
      maxPendingJobs: 1,
      queueOnBackpressure: true,
      maxQueuedJobs: 1,
    })

    FakeWorker.modes.push('silent')
    const pending = api.sha512(new Uint8Array([1]))
    const buffered = api.sha512(new Uint8Array([2]))

    await api.close()

    await expect(pending).rejects.toThrow('async worker pool is closed')
    await expect(buffered).rejects.toThrow('async worker pool is closed')
  })

  it('covers stale-worker revive guard and terminate loop wait path', async () => {
    const { createSignalAsync } = await loadDualApi()
    FakeWorker.disableRemoveAll = true

    const api = await createSignalAsync({ workers: 1, maxPendingJobs: 1 })
    const oldWorker = FakeWorker.instances[0]!
    oldWorker.emit('error', new Error('first-crash'))
    expect(FakeWorker.instances.length).toBeGreaterThan(1)

    // same old worker emits again after replacement => stale worker guard path
    oldWorker.emit('error', new Error('stale-crash'))

    await api.close()
    await expect(api.__terminateWorkerForTest?.(0)).rejects.toThrow('async worker crashed while processing jobs')
  })
})

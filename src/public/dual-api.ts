import { Worker } from 'node:worker_threads'
import { crypto } from '../crypto'

export interface SignalSyncAPI {
    readonly encrypt: typeof crypto.encrypt
    readonly decrypt: typeof crypto.decrypt
    readonly hkdf: typeof crypto.hkdf
    readonly sha512: typeof crypto.sha512
    readonly hmacSha256: typeof crypto.hmacSha256
}

export interface SignalAsyncAPI {
    encrypt: (key: Uint8Array, plaintext: Uint8Array, options?: { readonly aad?: Uint8Array; readonly iv?: Uint8Array }) => Promise<{ ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array }>
    decrypt: (key: Uint8Array, data: { readonly ciphertext: Uint8Array; readonly iv: Uint8Array; readonly tag: Uint8Array }, options?: { readonly aad?: Uint8Array }) => Promise<Uint8Array>
    hkdf: (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, options: { readonly length: number }) => Promise<Uint8Array>
    sha512: (data: Uint8Array) => Promise<Uint8Array>
    hmacSha256: (key: Uint8Array, data: Uint8Array) => Promise<Uint8Array>
    getWorkerInfo(): Promise<{ readonly threadId: number; readonly isMainThread: boolean }>
    /** @internal Test-only helper to simulate abrupt worker termination. */
    __terminateWorkerForTest?(workerIndex?: number): Promise<void>
    close(): Promise<void>
}

export interface CreateSignalAsyncOptions {
    readonly workers?: number
    readonly maxPendingJobs?: number
}

type SignalWorkerRequest =
    | { readonly type: 'encrypt'; readonly payload: { readonly key: Uint8Array; readonly plaintext: Uint8Array; readonly options?: { readonly aad?: Uint8Array; readonly iv?: Uint8Array } } }
    | { readonly type: 'decrypt'; readonly payload: { readonly key: Uint8Array; readonly data: { readonly ciphertext: Uint8Array; readonly iv: Uint8Array; readonly tag: Uint8Array }; readonly options?: { readonly aad?: Uint8Array } } }
    | { readonly type: 'sha512'; readonly payload: { readonly data: Uint8Array } }
    | { readonly type: 'hmacSha256'; readonly payload: { readonly key: Uint8Array; readonly data: Uint8Array } }
    | { readonly type: 'hkdf'; readonly payload: { readonly ikm: Uint8Array; readonly salt: Uint8Array; readonly info: Uint8Array; readonly options: { readonly length: number } } }
    | { readonly type: 'threadInfo'; readonly payload: {} }

type WorkerResultMap = {
    readonly encrypt: { readonly ciphertext: Uint8Array; readonly iv: Uint8Array; readonly tag: Uint8Array }
    readonly decrypt: Uint8Array
    readonly sha512: Uint8Array
    readonly hmacSha256: Uint8Array
    readonly hkdf: Uint8Array
    readonly threadInfo: { readonly threadId: number; readonly isMainThread: boolean }
}

type SignalWorkerResponse<K extends keyof WorkerResultMap = keyof WorkerResultMap> =
    | { readonly ok: true; readonly type: K; readonly value: WorkerResultMap[K] }
    | { readonly ok: false; readonly message: string }

type WorkerEnvelope<K extends keyof WorkerResultMap = keyof WorkerResultMap> = {
    readonly id: number
    readonly response: SignalWorkerResponse<K>
}

type PendingJob = {
    readonly workerIndex: number
    readonly reject: (error: Error) => void
    readonly resolve: (value: unknown) => void
}

interface WorkerState {
    worker: Worker
    pendingCount: number
    alive: boolean
}

const WORKER_CRASH_ERROR = 'async worker crashed while processing jobs'

function createWorker(): Worker {
    // TODO(protocol-risk): keep worker-by-file (no eval) to avoid reintroducing dynamic worker source execution.
    // Node resolves ESM here from the .mjs worker entrypoint URL.
    return new Worker(new URL('./signal-worker.mjs', import.meta.url))
}

export function createSignalSync(): SignalSyncAPI {
    return {
        encrypt: crypto.encrypt,
        decrypt: crypto.decrypt,
        hkdf: crypto.hkdf,
        sha512: crypto.sha512,
        hmacSha256: crypto.hmacSha256,
    }
}

export async function createSignalAsync(options: CreateSignalAsyncOptions = {}): Promise<SignalAsyncAPI> {
    const workerCount = options.workers ?? 1
    if (!Number.isInteger(workerCount) || workerCount <= 0) throw new Error('workers must be a positive integer')

    const maxPendingJobs = options.maxPendingJobs ?? workerCount * 64
    if (!Number.isInteger(maxPendingJobs) || maxPendingJobs <= 0) throw new Error('maxPendingJobs must be a positive integer')

    const maxPendingPerWorker = Math.max(1, Math.floor(maxPendingJobs / workerCount))

    const workers: WorkerState[] = []
    const pending = new Map<number, PendingJob>()
    let nextRequestId = 1
    let roundRobin = 0
    let closed = false

    const rejectWorkerJobs = (workerIndex: number, reason: Error): void => {
        for (const [id, job] of pending) {
            if (job.workerIndex !== workerIndex) continue
            pending.delete(id)
            job.reject(reason)
        }
    }

    const attachHandlers = (state: WorkerState, workerIndex: number): void => {
        const worker = state.worker

        worker.on('message', (envelope: WorkerEnvelope) => {
            const job = pending.get(envelope.id)
            if (!job) return
            pending.delete(envelope.id)
            state.pendingCount = Math.max(0, state.pendingCount - 1)

            if (!envelope.response.ok) {
                job.reject(new Error(envelope.response.message))
                return
            }

            job.resolve(envelope.response.value)
        })

        const reviveWorker = (): void => {
            if (closed) return
            if (state.worker !== worker) return
            state.alive = false
            rejectWorkerJobs(workerIndex, new Error(WORKER_CRASH_ERROR))
            state.pendingCount = 0
            worker.removeAllListeners()
            state.worker = createWorker()
            state.alive = true
            attachHandlers(state, workerIndex)
        }

        worker.on('error', reviveWorker)
        worker.on('exit', () => {
            if (closed) return
            reviveWorker()
        })
    }

    for (let i = 0; i < workerCount; i++) {
        const state: WorkerState = { worker: createWorker(), pendingCount: 0, alive: true }
        workers.push(state)
        attachHandlers(state, i)
    }

    const run = async <K extends keyof WorkerResultMap>(request: Extract<SignalWorkerRequest, { readonly type: K }>): Promise<WorkerResultMap[K]> => {
        if (closed) throw new Error('async worker pool is closed')
        let selectedIndex = -1
        for (let i = 0; i < workers.length; i++) {
            const candidateIndex = (roundRobin + i) % workers.length
            const candidate = workers[candidateIndex]!
            if (!candidate.alive) continue
            if (candidate.pendingCount >= maxPendingPerWorker) continue
            selectedIndex = candidateIndex
            break
        }

        if (selectedIndex < 0) {
            throw new Error('async worker backpressure: too many pending jobs')
        }

        const state = workers[selectedIndex]!
        roundRobin = selectedIndex + 1

        const id = nextRequestId++
        state.pendingCount += 1

        return await new Promise<WorkerResultMap[K]>((resolve, reject) => {
            pending.set(id, {
                workerIndex: selectedIndex,
                reject,
                resolve: resolve as (value: unknown) => void,
            })

            state.worker.postMessage({ id, request })
        })
    }

    return {
        encrypt: (key, plaintext, options) => run({ type: 'encrypt', payload: options ? { key, plaintext, options } : { key, plaintext } }),
        decrypt: (key, data, options) => run({ type: 'decrypt', payload: options ? { key, data, options } : { key, data } }),
        sha512: (data) => run({ type: 'sha512', payload: { data } }),
        hmacSha256: (key, data) => run({ type: 'hmacSha256', payload: { key, data } }),
        hkdf: (ikm, salt, info, options) => run({ type: 'hkdf', payload: { ikm, salt, info, options } }),
        getWorkerInfo: () => run({ type: 'threadInfo', payload: {} }),
        __terminateWorkerForTest: async (workerIndex = 0) => {
            const state = workers[workerIndex]
            if (!state) {
                throw new Error('worker index out of range')
            }

            const crashError = new Error(WORKER_CRASH_ERROR)
            const syntheticPending = new Promise<void>((resolve, reject) => {
                const syntheticId = nextRequestId++
                state.pendingCount += 1
                pending.set(syntheticId, {
                    workerIndex,
                    resolve: () => reject(new Error('synthetic crash job unexpectedly resolved')),
                    reject: (error) => {
                        if (error.message === WORKER_CRASH_ERROR) {
                            resolve()
                            return
                        }
                        reject(error)
                    }
                })
            })

            rejectWorkerJobs(workerIndex, crashError)
            state.pendingCount = 0
            const crashedWorker = state.worker
            await crashedWorker.terminate()
            await syntheticPending

            for (let i = 0; i < 20; i++) {
                if (state.worker !== crashedWorker && state.alive) {
                    break
                }
                await new Promise((resolve) => setTimeout(resolve, 10))
            }

            throw crashError
        },
        close: async () => {
            closed = true
            for (const [, job] of pending) {
                job.reject(new Error('async worker pool is closed'))
            }
            pending.clear()
            await Promise.all(
                workers.map(async (state) => {
                    state.alive = false
                    await state.worker.terminate()
                })
            )
        },
    }
}

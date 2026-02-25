import { Deque } from './internal/queue/deque'
import { getSignalLogger } from './internal/logger'

export type Job<T> = (signal: AbortSignal) => Promise<T>

interface QueuedJob<T> {
    job: Job<T>
    resolve: (value: T) => void
    reject: (reason?: unknown) => void
    timeoutMs: number | undefined
}

interface QueueState {
    queue: Deque<QueuedJob<unknown>>
    running: boolean
}

export interface EnqueueOptions {
    timeoutMs?: number
}

/**
 * Enqueue a barrier job that resolves only after all currently queued jobs
 * for the bucket have completed.
 */
export function flushQueue(bucket: unknown): Promise<void> {
    return enqueue(bucket, async () => undefined)
}

const queueBuckets = new Map<unknown, QueueState>()

function createTimeoutController(timeoutMs: number | undefined): {
    controller: AbortController
    timeoutId: NodeJS.Timeout | undefined
} {
    const controller = new AbortController()
    if (timeoutMs === undefined) {
        return { controller, timeoutId: undefined }
    }

    const timeoutId = setTimeout(() => {
        getSignalLogger()?.debug('queue-timeout', { timeoutMs })
        controller.abort(new Error(`queue job timeout after ${timeoutMs}ms`))
    }, timeoutMs)

    return { controller, timeoutId }
}

async function runQueuedJob<T>(entry: QueuedJob<T>): Promise<T> {
    const { controller, timeoutId } = createTimeoutController(entry.timeoutMs)

    try {
        return await entry.job(controller.signal)
    } catch (error) {
        if (controller.signal.aborted && controller.signal.reason instanceof Error) {
            throw controller.signal.reason
        }
        throw error
    } finally {
        if (timeoutId) {
            clearTimeout(timeoutId)
        }
    }
}

async function executeQueuedJob(job: QueuedJob<unknown>): Promise<void> {
    try {
        const result = await runQueuedJob(job)
        job.resolve(result)
    } catch (err) {
        job.reject(err)
    }
}

async function asyncQueueExecutor(bucket: unknown, state: QueueState): Promise<void> {
    const queue = state.queue

    try {
        while (queue.length > 0) {
            const job = queue.shift()
            if (!job) {
                continue
            }
            await executeQueuedJob(job)
        }
    } finally {
        state.running = false
        if (queue.length === 0) {
            queueBuckets.delete(bucket)
        }
    }
}

export function enqueue<T>(bucket: unknown, job: Job<T>, options?: EnqueueOptions): Promise<T> {
    let state = queueBuckets.get(bucket)

    if (!state) {
        state = { queue: new Deque<QueuedJob<unknown>>(), running: false }
        queueBuckets.set(bucket, state)
    }

    const timeoutMs = options?.timeoutMs
    if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs <= 0)) {
        throw new TypeError('timeoutMs must be a positive integer')
    }

    const jobPromise = new Promise<T>((resolve, reject) => {
        const wrappedJob: QueuedJob<unknown> = {
            job: job as Job<unknown>,
            resolve: resolve as (value: unknown) => void,
            reject,
            timeoutMs,
        }
        state.queue.push(wrappedJob)
        getSignalLogger()?.debug('queue-size', { size: state.queue.length })
    })

    if (!state.running) {
        state.running = true
        void asyncQueueExecutor(bucket, state)
    }

    return jobPromise
}

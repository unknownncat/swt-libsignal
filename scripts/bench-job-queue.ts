import { performance } from 'node:perf_hooks'
import { Deque } from '../src/internal/queue/deque.ts'

interface Sample {
    ms: number
    heapDelta: number
}

interface BenchmarkResult {
    readonly name: string
    readonly iterations: number
    readonly rounds: number
    readonly warmupRounds: number
    readonly avgMs: number
    readonly p95Ms: number
    readonly avgHeapDelta: number
    readonly opsPerSec: number
    readonly samples: readonly Sample[]
}

type BenchFn = (iterations: number) => void

function ensureGc(): void {
    if (typeof global.gc !== 'function') {
        throw new Error(
            'Run with: node --expose-gc ./node_modules/.bin/tsx scripts/bench-job-queue.ts'
        )
    }
}

function percentile(values: readonly number[], p: number): number {
    if (values.length === 0) return 0
    const sorted = [...values].sort((a, b) => a - b)
    const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
    return sorted[idx] ?? 0
}

function benchmark(
    name: string,
    fn: BenchFn,
    iterations: number,
    warmupRounds: number,
    rounds: number
): BenchmarkResult {
    for (let i = 0; i < warmupRounds; i++) {
        fn(iterations)
    }

    const samples: Sample[] = []

    for (let i = 0; i < rounds; i++) {
        global.gc?.()
        const before = process.memoryUsage().heapUsed

        const t0 = performance.now()
        fn(iterations)
        const t1 = performance.now()

        global.gc?.()
        const after = process.memoryUsage().heapUsed

        samples.push({
            ms: t1 - t0,
            heapDelta: after - before,
        })
    }

    const ms = samples.map((s) => s.ms)
    const heaps = samples.map((s) => s.heapDelta)

    const avgMs = ms.reduce((a, b) => a + b, 0) / ms.length
    const avgHeapDelta = heaps.reduce((a, b) => a + b, 0) / heaps.length
    const opsPerSec = (iterations / avgMs) * 1000

    return {
        name,
        iterations,
        rounds,
        warmupRounds,
        avgMs,
        p95Ms: percentile(ms, 95),
        avgHeapDelta,
        opsPerSec,
        samples,
    }
}

//
// 🔹 SCENARIO 1 — Drain completo
//
function arrayDrain(iterations: number): void {
    const q: number[] = []
    for (let i = 0; i < iterations; i++) q.push(i)
    while (q.length > 0) q.shift()
}

function dequeDrain(iterations: number): void {
    const q = new Deque<number>()
    for (let i = 0; i < iterations; i++) q.push(i)
    while (q.length > 0) q.shift()
}

//
// 🔹 SCENARIO 2 — Mixed 50/50
//
function arrayMixed(iterations: number): void {
    const q: number[] = []
    for (let i = 0; i < iterations; i++) {
        q.push(i)
        if ((i & 1) === 0) q.shift()
    }
}

function dequeMixed(iterations: number): void {
    const q = new Deque<number>()
    for (let i = 0; i < iterations; i++) {
        q.push(i)
        if ((i & 1) === 0) q.shift()
    }
}

//
// 🔹 SCENARIO 3 — Steady state
//
function arraySteady(iterations: number): void {
    const q: number[] = []
    const size = 1024

    for (let i = 0; i < size; i++) q.push(i)

    for (let i = 0; i < iterations; i++) {
        q.shift()
        q.push(i)
    }
}

function dequeSteady(iterations: number): void {
    const q = new Deque<number>()
    const size = 1024

    for (let i = 0; i < size; i++) q.push(i)

    for (let i = 0; i < iterations; i++) {
        q.shift()
        q.push(i)
    }
}

//
// 🔹 SCENARIO 4 — Burst pattern
//
function arrayBurst(iterations: number): void {
    const q: number[] = []
    const burst = 1000
    const cycles = Math.floor(iterations / burst)

    for (let c = 0; c < cycles; c++) {
        for (let i = 0; i < burst; i++) q.push(i)
        for (let i = 0; i < burst; i++) q.shift()
    }
}

function dequeBurst(iterations: number): void {
    const q = new Deque<number>()
    const burst = 1000
    const cycles = Math.floor(iterations / burst)

    for (let c = 0; c < cycles; c++) {
        for (let i = 0; i < burst; i++) q.push(i)
        for (let i = 0; i < burst; i++) q.shift()
    }
}

const isTestMode = process.env.BENCH_TEST_MODE === '1'
if (!isTestMode) {
    ensureGc()
}
const iterations = isTestMode ? 5_000 : 200_000
const warmupRounds = isTestMode ? 1 : 5
const rounds = isTestMode ? 2 : 20

const results = [
    benchmark('array-drain', arrayDrain, iterations, warmupRounds, rounds),
    benchmark('deque-drain', dequeDrain, iterations, warmupRounds, rounds),

    benchmark('array-mixed', arrayMixed, iterations, warmupRounds, rounds),
    benchmark('deque-mixed', dequeMixed, iterations, warmupRounds, rounds),

    benchmark('array-steady', arraySteady, iterations, warmupRounds, rounds),
    benchmark('deque-steady', dequeSteady, iterations, warmupRounds, rounds),

    benchmark('array-burst', arrayBurst, iterations, warmupRounds, rounds),
    benchmark('deque-burst', dequeBurst, iterations, warmupRounds, rounds),
]

console.log(JSON.stringify({
    meta: {
        node: process.version,
        exposeGc: typeof global.gc === 'function',
        iterations,
        rounds,
    },
    results,
}, null, 2))

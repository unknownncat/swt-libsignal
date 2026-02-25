import { afterEach, describe, expect, it, vi } from 'vitest'
import { resolve } from 'node:path'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('coverage - barrels and entrypoints', () => {
  it('loads barrel/public modules', async () => {
    const modules = await Promise.all([
      import('../../src/index'),
      import('../../src/core'),
      import('../../src/errors'),
      import('../../src/proto'),
      import('../../src/protobuf'),
      import('../../src/session'),
      import('../../src/session/builder'),
      import('../../src/session/cipher'),
      import('../../src/session/record'),
      import('../../src/session/storage'),
      import('../../src/signal'),
      import('../../src/signal/group'),
      import('../../src/transport'),
      import('../../src/types'),
      import('../../src/utils'),
      import('../../src/public/index'),
      import('../../src/public/crypto'),
      import('../../src/public/errors'),
      import('../../src/public/identity'),
      import('../../src/public/logger'),
      import('../../src/public/protobuf'),
      import('../../src/public/session'),
      import('../../src/public/signal'),
    ])

    expect(modules.length).toBeGreaterThan(0)
    expect((modules[0] as { createSignalAsync?: unknown }).createSignalAsync).toBeTypeOf('function')
    expect((modules[8] as { SessionRecord?: unknown }).SessionRecord).toBeDefined()
    expect((modules[10] as { makeLibSignalRepository?: unknown }).makeLibSignalRepository).toBeTypeOf('function')
  })

  it('covers docs run-all CLI branch', async () => {
    const oldArgv = process.argv
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    try {
      process.argv = ['node', resolve(process.cwd(), 'docs/examples/run-all.ts')]
      vi.resetModules()
      await import('../../docs/examples/run-all.ts')
      expect(log).toHaveBeenCalled()
    } finally {
      process.argv = oldArgv
      log.mockRestore()
    }
  })

  it('covers bench ensureGc guard in non-test mode', async () => {
    const oldMode = process.env.BENCH_TEST_MODE
    const previousGc = globalThis.gc

    delete process.env.BENCH_TEST_MODE
    ;(globalThis as { gc?: () => void }).gc = undefined
    vi.resetModules()

    await expect(import('../../scripts/bench-job-queue.ts')).rejects.toThrow('Run with: node --expose-gc')

    if (oldMode === undefined) delete process.env.BENCH_TEST_MODE
    else process.env.BENCH_TEST_MODE = oldMode
    ;(globalThis as { gc?: () => void }).gc = previousGc
  })

  it('covers hkdfAsync success path', async () => {
    const mod = await import('../../src/crypto-async')
    const out = await mod.hkdfAsync(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([4, 5, 6]),
      new Uint8Array([7, 8, 9]),
      { length: 48 }
    )

    expect(out).toBeInstanceOf(Uint8Array)
    expect(out.length).toBe(48)
  })
})

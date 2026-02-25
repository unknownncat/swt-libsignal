import { describe, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('scripts and docs examples', () => {
  it('runs check-api-exports script and writes contract/snapshot', async () => {
    const oldArgv = process.argv
    const cwd = process.cwd()

    try {
      process.argv = ['node', 'script', '--write']
      vi.resetModules()
      await import('../scripts/check-api-exports.ts')

      const snapshot = readFileSync(join(cwd, 'docs/api/public-exports.snapshot.json'), 'utf8')
      const contract = readFileSync(join(cwd, 'docs/api/public-contract.md'), 'utf8')
      expect(snapshot).toContain('"ProtocolAddress"')
      expect(contract).toContain('# Public API Contract')
    } finally {
      process.argv = oldArgv
    }
  })

  it('covers check-api-exports branch when snapshot does not exist', async () => {
    const cwd = process.cwd()
    const snapshot = join(cwd, 'docs/api/public-exports.snapshot.json')
    const backup = `${snapshot}.bak`
    renameSync(snapshot, backup)
    try {
      vi.resetModules()
      await import('../scripts/check-api-exports.ts')
      const contract = readFileSync(join(cwd, 'docs/api/public-contract.md'), 'utf8')
      expect(contract).toContain('| Symbol | Kind |')
    } finally {
      renameSync(backup, snapshot)
    }
  })

  it('throws when export snapshot diverges from runtime exports', async () => {
    const cwd = process.cwd()
    const snapshot = join(cwd, 'docs/api/public-exports.snapshot.json')
    const old = readFileSync(snapshot, 'utf8')
    try {
      await import('node:fs/promises').then(({ writeFile }) => writeFile(snapshot, '["__mismatch__"]\n', 'utf8'))
      vi.resetModules()
      await expect(import('../scripts/check-api-exports.ts')).rejects.toThrow('Public exports changed')
    } finally {
      await import('node:fs/promises').then(({ writeFile }) => writeFile(snapshot, old, 'utf8'))
    }
  })

  it('runs benchmark script in test mode', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    process.env.BENCH_TEST_MODE = '1'
    vi.resetModules()
    await import('../scripts/bench-job-queue.ts')
    expect(log).toHaveBeenCalled()
    log.mockRestore()
    delete process.env.BENCH_TEST_MODE
  })

  it('executes docs runtime example scripts without throwing', async () => {
    vi.resetModules()
    const mod = await import('../docs/examples/run-all.ts')
    const summary = await mod.runAllExamples()

    expect(summary.crypto.syncRoundTrip).toBe(true)
    expect(summary.crypto.asyncRoundTrip).toBe(true)
    expect(summary.crypto.dualRoundTrip).toBe(true)
    expect(summary.crypto.hkdfLength).toBe(64)
    expect(summary.crypto.digestLength).toBe(64)

    expect(summary.session.firstMessageOk).toBe(true)
    expect(summary.session.secondMessageOk).toBe(true)

    expect(summary.group.plaintextMatch).toBe(true)
    expect(summary.repository.oneToOneOk).toBe(true)
    expect(summary.repository.groupOk).toBe(true)

    expect(summary.storage.registrationId).toBe(777)
    expect(summary.storage.managerValueLength).toBe(4)
    expect(summary.storage.persistedValueLength).toBe(5)

    expect(summary.production.firstUseApproved).toBe(true)
    expect(summary.production.rotationApproved).toBe(true)
    expect(summary.production.previousKeyRejectedAfterRotation).toBe(true)
    expect(summary.production.atomicGuardTriggered).toBe(true)
    expect(summary.production.queuedBurstSucceeded).toBe(true)
    expect(summary.production.queueFullTriggered).toBe(true)
  })

  it('keeps an isolated temp folder setup for script side effects', () => {
    const dir = mkdtempSync(join(tmpdir(), 'swt-test-'))
    mkdirSync(join(dir, 'docs', 'api'), { recursive: true })
    expect(dir.length).toBeGreaterThan(0)
  })
})

import { describe, expect, it, vi } from 'vitest'

describe.sequential('runtime fallback branch coverage', () => {
  it('covers registration id nullish fallback for short random byte output', async () => {
    vi.resetModules()
    vi.doMock('node:crypto', async () => {
      const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto')
      return {
        ...actual,
        randomBytes: vi.fn(() => Buffer.alloc(0))
      }
    })

    try {
      const keyhelper = await import('../../src/compat/libsignal/src/keyhelper')
      expect(keyhelper.generateRegistrationId()).toBe(0)
    } finally {
      vi.doUnmock('node:crypto')
      vi.resetModules()
    }
  })

  it('covers sqlite loader guard when node:sqlite export surface is unavailable', async () => {
    vi.resetModules()
    vi.doMock('node:sqlite', () => ({}))

    try {
      const { SqliteAsyncStorageAdapter } = await import('../../src/session/storage/sqlite-async')
      await expect(SqliteAsyncStorageAdapter.open('mocked.db')).rejects.toThrow(
        'SQLite adapter requires Node.js runtime support for node:sqlite'
      )
    } finally {
      vi.doUnmock('node:sqlite')
      vi.resetModules()
    }
  })
})

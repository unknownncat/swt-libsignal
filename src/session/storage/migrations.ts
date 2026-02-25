import type { AsyncStorageAdapter, StorageAdapter } from './types'

function hasMigrate(adapter: StorageAdapter): adapter is AsyncStorageAdapter {
    return typeof (adapter as AsyncStorageAdapter).migrate === 'function'
}

export async function runMigrations(adapter: StorageAdapter, fromVersion: number, toVersion: number): Promise<void> {
    if (!hasMigrate(adapter)) return
    await adapter.migrate!(fromVersion, toVersion)
}

import { mkdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import {
  AtomicJsonFileAsyncStorageAdapter,
  createSessionStorage,
  createStorageManager,
  InMemoryStorage
} from '../../src/session/storage'

export interface StorageRuntimeCheckResult {
  readonly registrationId: number
  readonly managerValueLength: number
  readonly persistedValueLength: number
}

export async function runStorageRuntimeCheck(): Promise<StorageRuntimeCheckResult> {
  const memoryAdapter = new InMemoryStorage<unknown>()
  const sessionStore = createSessionStorage(memoryAdapter)
  await sessionStore.storeBootstrap(
    { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
    777
  )

  const manager = createStorageManager(new InMemoryStorage<Uint8Array>())
  await manager.set('demo', new Uint8Array([1, 2, 3, 4]))
  const managerValue = await manager.get('demo')

  const tmpDir = join(process.cwd(), 'tmp')
  await mkdir(tmpDir, { recursive: true })
  const filePath = join(tmpDir, 'docs-storage-runtime.json')
  const fileAdapter = new AtomicJsonFileAsyncStorageAdapter(filePath, { flushEveryWrites: 1 })

  try {
    await fileAdapter.set('persisted', new Uint8Array([9, 8, 7, 6, 5]))
    const persisted = await fileAdapter.get('persisted')
    await fileAdapter.close()

    return {
      registrationId: await sessionStore.getOurRegistrationId(),
      managerValueLength: managerValue?.length ?? 0,
      persistedValueLength: persisted?.length ?? 0,
    }
  } finally {
    await fileAdapter.close()
    await rm(filePath, { force: true })
  }
}

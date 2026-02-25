import { createSignalAsync } from '../../src/public/dual-api'
import { SessionRecord } from '../../src/session/record'
import { createSessionStorage } from '../../src/session/storage/adapter'
import { InMemoryStorage } from '../../src/session/storage/in-memory'

export interface ProductionReadinessRuntimeCheckResult {
  readonly firstUseApproved: boolean
  readonly rotationApproved: boolean
  readonly previousKeyRejectedAfterRotation: boolean
  readonly atomicGuardTriggered: boolean
  readonly queuedBurstSucceeded: boolean
  readonly queueFullTriggered: boolean
}

export async function runProductionReadinessRuntimeCheck(): Promise<ProductionReadinessRuntimeCheckResult> {
  const store = createSessionStorage(new InMemoryStorage<unknown>(), {
    trustOnFirstUse: false,
    onFirstUseIdentity: async () => true,
    onIdentityMismatch: async () => 'replace',
  })

  const first = new Uint8Array([1, 1, 1])
  const rotated = new Uint8Array([2, 2, 2])
  const firstUseApproved = await store.isTrustedIdentity('peer', first)
  const rotationApproved = await store.isTrustedIdentity('peer', rotated)

  const strictMismatchStore = createSessionStorage(new InMemoryStorage<unknown>(), {
    trustOnFirstUse: true,
    onIdentityMismatch: async () => 'reject',
  })
  await strictMismatchStore.isTrustedIdentity('peer', first)
  const previousKeyRejectedAfterRotation = await strictMismatchStore.isTrustedIdentity('peer', rotated)

  const strictAtomicStore = createSessionStorage(new InMemoryStorage<unknown>(), {
    requireAtomicSessionAndPreKey: true,
  })
  let atomicGuardTriggered = false
  try {
    await strictAtomicStore.storeSessionAndRemovePreKey('peer.1', new SessionRecord(), 77)
  } catch (error) {
    atomicGuardTriggered = String(error).includes('Atomic session+prekey operation requires adapter.transaction() support')
  }

  const queuedApi = await createSignalAsync({
    workers: 1,
    maxPendingJobs: 1,
    queueOnBackpressure: true,
    maxQueuedJobs: 4,
  })

  let queuedBurstSucceeded = false
  try {
    const key = new Uint8Array(32).fill(9)
    const data = new Uint8Array(512 * 1024).fill(3)
    const burst = await Promise.all([
      queuedApi.encrypt(key, data, { iv: new Uint8Array(12).fill(1) }),
      queuedApi.encrypt(key, data, { iv: new Uint8Array(12).fill(2) }),
      queuedApi.encrypt(key, data, { iv: new Uint8Array(12).fill(3) }),
    ])
    queuedBurstSucceeded = burst.length === 3
  } finally {
    await queuedApi.close()
  }

  const queueFullApi = await createSignalAsync({
    workers: 1,
    maxPendingJobs: 1,
    queueOnBackpressure: true,
    maxQueuedJobs: 1,
  })

  let queueFullTriggered = false
  try {
    const key = new Uint8Array(32).fill(5)
    const data = new Uint8Array(512 * 1024).fill(4)
    const jobs = Array.from({ length: 8 }, (_, idx) =>
      queueFullApi.encrypt(key, data, { iv: new Uint8Array(12).fill((idx % 200) + 10) }),
    )
    const settled = await Promise.allSettled(jobs)
    queueFullTriggered = settled.some(
      (result) => result.status === 'rejected' && String(result.reason).includes('async worker backpressure queue full'),
    )
  } finally {
    await queueFullApi.close()
  }

  return {
    firstUseApproved,
    rotationApproved,
    previousKeyRejectedAfterRotation: previousKeyRejectedAfterRotation === false,
    atomicGuardTriggered,
    queuedBurstSucceeded,
    queueFullTriggered,
  }
}

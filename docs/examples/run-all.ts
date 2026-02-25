import { pathToFileURL } from 'node:url'
import { runCryptoRuntimeCheck } from './crypto-runtime-check'
import { runGroupRuntimeCheck } from './group-runtime-check'
import { runRepositoryRuntimeCheck } from './repository-runtime-check'
import { runSessionRuntimeCheck } from './session-runtime-check'
import { runStorageRuntimeCheck } from './storage-runtime-check'

export interface DocsRuntimeSummary {
  readonly crypto: Awaited<ReturnType<typeof runCryptoRuntimeCheck>>
  readonly session: Awaited<ReturnType<typeof runSessionRuntimeCheck>>
  readonly group: Awaited<ReturnType<typeof runGroupRuntimeCheck>>
  readonly repository: Awaited<ReturnType<typeof runRepositoryRuntimeCheck>>
  readonly storage: Awaited<ReturnType<typeof runStorageRuntimeCheck>>
}

export async function runAllExamples(): Promise<DocsRuntimeSummary> {
  return {
    crypto: await runCryptoRuntimeCheck(),
    session: await runSessionRuntimeCheck(),
    group: await runGroupRuntimeCheck(),
    repository: await runRepositoryRuntimeCheck(),
    storage: await runStorageRuntimeCheck(),
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const summary = await runAllExamples()
  console.log(JSON.stringify(summary, null, 2))
}

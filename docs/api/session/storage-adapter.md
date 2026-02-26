# Storage adapter

Camadas principais:

- `InMemoryStorage<T>`
- `AtomicJsonFileAsyncStorageAdapter`
- `SqliteAsyncStorageAdapter`
- `createSessionStorage(adapter, options)`
- `createStorageManager(adapter)`

`createSessionStorage` suporta opções de hardening:

- `trustOnFirstUse`
- `onFirstUseIdentity`
- `onIdentityMismatch`
- `requireAtomicSessionAndPreKey`

## Exemplo

```ts
import { InMemoryStorage, createSessionStorage } from '../../../src/session/storage'

const adapter = new InMemoryStorage<unknown>()
const storage = createSessionStorage(adapter, {
  trustOnFirstUse: false,
  onFirstUseIdentity: async () => true,
  onIdentityMismatch: async () => 'reject',
  requireAtomicSessionAndPreKey: false,
})

await storage.storeBootstrap(
  { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(64).fill(2) },
  777
)
```

Explicação: `trustOnFirstUse: false` desabilita TOFU automático, `onFirstUseIdentity` permite aprovação explícita da primeira chave remota e `onIdentityMismatch` define política para rotação de identidade.

## SQLite assíncrono transacional

```ts
import { SqliteAsyncStorageAdapter, createSessionStorage } from '../../../src/session/storage'

const adapter = await SqliteAsyncStorageAdapter.open<unknown>('./tmp/swt.db', {
  walMode: 'WAL',
  synchronous: 'FULL',
  secureDelete: true,
})

const storage = createSessionStorage(adapter, {
  requireAtomicSessionAndPreKey: true,
})
```

Explicação: o adapter SQLite fornece transação explícita para `storeSessionAndRemovePreKey`, reduzindo risco de estado parcial em falhas.

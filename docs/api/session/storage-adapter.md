# Storage adapter

Camadas principais:

- `InMemoryStorage<T>`
- `AtomicJsonFileAsyncStorageAdapter`
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

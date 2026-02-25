# Storage adapter

Camadas principais:

- `InMemoryStorage<T>`
- `AtomicJsonFileAsyncStorageAdapter`
- `createSessionStorage(adapter, options)`
- `createStorageManager(adapter)`

## Exemplo

```ts
import { InMemoryStorage, createSessionStorage } from '../../../src/session/storage'

const adapter = new InMemoryStorage<unknown>()
const storage = createSessionStorage(adapter, { trustOnFirstUse: false })

await storage.storeBootstrap(
  { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
  777
)
```

Explicação: o exemplo mostra bootstrap de identidade local e opção para desabilitar TOFU automático.

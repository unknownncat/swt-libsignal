# Storage adapter

> Esta seção é voltada ao desenvolvimento do projeto (monorepo), usando imports internos de `src/session/storage`.

## Blocos principais

- `InMemoryStorage<T>`: adapter em memória com cópia defensiva.
- `AtomicJsonFileAsyncStorageAdapter`: persistência assíncrona em arquivo JSON.
- `createSessionStorage(adapter)`: contrato usado por sessão.
- `createStorageManager(adapter)`: wrapper genérico de acesso.
- `runMigrations(adapter, from, to)`: executa `migrate` quando disponível.

## Exemplo com InMemoryStorage

```ts
import { InMemoryStorage, createSessionStorage } from '../../src/session/storage'

const raw = new InMemoryStorage<unknown>()
const storage = createSessionStorage(raw)

await storage.storeBootstrap(
  { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
  777,
)

const regId = await storage.getOurRegistrationId()
console.log(regId)
```

## Exemplo com adapter assíncrono em arquivo

```ts
import { AtomicJsonFileAsyncStorageAdapter } from '../../src/session/storage'

const adapter = new AtomicJsonFileAsyncStorageAdapter(
  './tmp/signal-storage.json',
  { flushEveryWrites: 1 },
)

await adapter.set('k', new Uint8Array([1, 2, 3]))
console.log(await adapter.get('k'))
await adapter.close()
```

## Descarte seguro

```ts
await adapter.zeroize?.('k')
await adapter.clear?.({ secure: true })
```

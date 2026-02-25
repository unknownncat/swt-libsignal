# Sync vs Async

## Quando usar `sync`

- Carga baixa/média.
- Fluxos curtos no mesmo thread.
- Menor overhead operacional.

## Quando usar `async`

- I/O ou CPU concorrente.
- Desejo de separar trabalho criptográfico via worker.
- APIs de storage assíncronas.

## Exemplo combinando as duas

```ts
import { createSignalSync, createSignalAsync } from '@unknownncat/swt-libsignal'

const syncApi = createSignalSync()
const asyncApi = await createSignalAsync({ workers: 1 })

const key = new Uint8Array(32).fill(5)
const msg = new TextEncoder().encode('dual')

const a = syncApi.encrypt(key, msg)
const b = await asyncApi.decrypt(key, a)

console.log(new TextDecoder().decode(b))
await asyncApi.close()
```

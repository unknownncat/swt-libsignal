# Sync vs Async

## Use sync quando

- O processo é simples e local.
- A latência mínima por operação é prioridade.

## Use async quando

- Você precisa isolar operações em worker.
- Há múltiplas tarefas criptográficas concorrentes.
- Você quer enfileirar bursts em vez de rejeitar chamadas sob backpressure.

## Exemplo

```ts
import { createSignalAsync, createSignalSync } from '@unknownncat/swt-libsignal'

const syncApi = createSignalSync()
const asyncApi = await createSignalAsync({
  workers: 1,
  maxPendingJobs: 64,
  queueOnBackpressure: true,
  maxQueuedJobs: 256,
})

const key = new Uint8Array(32).fill(5)
const msg = new TextEncoder().encode('dual')
const sealed = syncApi.encrypt(key, msg)
const opened = await asyncApi.decrypt(key, sealed)

await asyncApi.close()
```

Explicação: o exemplo combina `encrypt` sync e `decrypt` async no mesmo formato de pacote criptográfico.

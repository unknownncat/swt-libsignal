# Job queue

`enqueue(bucket, job)` executa jobs em série por bucket.

## Exemplo

```ts
import { enqueue } from '@unknownncat/swt-libsignal'

const order: number[] = []

await Promise.all([
  enqueue('peer.1', async () => { order.push(1) }),
  enqueue('peer.1', async () => { order.push(2) }),
])
```

Explicação: os jobs do mesmo bucket preservam ordem de execução e evitam corridas de estado.

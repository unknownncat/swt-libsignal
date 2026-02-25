# Job queue

`enqueue(bucket, job)` executa jobs em série por bucket, preservando ordem.

## Exemplo

```ts
import { enqueue, flushQueue } from '@unknownncat/swt-libsignal'

const order: number[] = []
await Promise.all([
  enqueue('sync', async () => { order.push(1); return 1 }),
  enqueue('sync', async () => { order.push(2); return 2 }),
])

await flushQueue('sync')
console.log(order) // [1, 2]
```

## Timeout

```ts
await enqueue('bucket', async (signal) => {
  if (signal.aborted) throw signal.reason
  return 'ok'
}, { timeoutMs: 50 })
```

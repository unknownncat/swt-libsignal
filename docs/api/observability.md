# Observability

Logger público:

- `setSignalLogger(logger)`

Contrato do logger:

- `debug(event, context?)`
- `info(event, context?)` (opcional)
- `warn(event, context?)`
- `error(event, context?)` (opcional)

Eventos atuais:

- `debug`: `queue-size`, `queue-timeout`, `ratchet-rotate`, `worker-dispatch`, `worker-buffered`, `worker-revive`
- `info`: `worker-ready`, `worker-close`
- `warn`: `identity-verification-failed`, `compat-fallback-used`, `worker-backpressure`
- `error`: `worker-crash`

Exemplo:

```ts
import { setSignalLogger } from '@unknownncat/swt-libsignal'

setSignalLogger({
  debug(event, context) {
    console.debug('[signal][debug]', event, context)
  },
  warn(event, context) {
    console.warn('[signal][warn]', event, context)
  },
})
```


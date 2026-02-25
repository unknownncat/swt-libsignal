# makeLibSignalRepository

`makeLibSignalRepository(store)` expõe uma API de alto nível para:

- `encryptMessage` e `decryptMessage` (1:1)
- `encryptGroupMessage` e `decryptGroupMessage` (grupo)
- `processSenderKeyDistributionMessage`
- `injectE2ESession`
- `validateSession`, `deleteSession`, `migrateSession`

## Exemplo

```ts
import { makeLibSignalRepository } from '@unknownncat/swt-libsignal'

const repository = makeLibSignalRepository(store)

await repository.injectE2ESession({ jid: 'bob.1', session: preKeyBundle })

const packet = await repository.encryptMessage({
  jid: 'bob.1',
  data: new TextEncoder().encode('hello'),
})
```

Explicação: o store precisa implementar os contratos de sessão e sender-key para o repositório operar em todos os fluxos.

# Signal layer

Esta seção documenta a camada de compatibilidade inspirada no `Baileys/src/Signal`, implementada sobre os módulos da biblioteca.

## Módulos

- `makeLibSignalRepository` para operações de sessão e grupo.
- `LIDMappingStore` para mapeamentos PN/LID.
- `signal/group/*` para Sender Keys (grupos).

## Exemplo rápido

```ts
import { makeLibSignalRepository } from '@unknownncat/swt-libsignal'

const repository = makeLibSignalRepository(store)
const encrypted = await repository.encryptMessage({
  jid: 'peer.1',
  data: new TextEncoder().encode('hello'),
})
```

Explicação: o repositório encapsula `SessionBuilder`, `SessionCipher` e fluxo de grupo num contrato único.

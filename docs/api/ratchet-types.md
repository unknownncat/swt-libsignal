# Ratchet types

Constantes públicas para tipar estado de sessão:

- `ChainType.SENDING`
- `ChainType.RECEIVING`
- `BaseKeyType.OURS`
- `BaseKeyType.THEIRS`

## Exemplo

```ts
import { ChainType, BaseKeyType } from '@unknownncat/swt-libsignal'

const sending = ChainType.SENDING
const ours = BaseKeyType.OURS

console.log(sending, ours)
```

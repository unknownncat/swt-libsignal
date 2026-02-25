# ProtocolAddress

Representa um destino lógico no formato `id.deviceId`.

## Exemplo

```ts
import { ProtocolAddress } from '@unknownncat/swt-libsignal'

const a = new ProtocolAddress('alice', 1)
const s = a.toString() // alice.1
const b = ProtocolAddress.from(s)

console.log(a.equals(b)) // true
```

## Regras

- `id` não pode ser vazio nem conter `.`
- `deviceId` deve ser inteiro seguro e não negativo

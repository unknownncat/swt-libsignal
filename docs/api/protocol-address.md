# ProtocolAddress

Representa um destino lógico no formato `id.deviceId`.

## Exemplo

```ts
import { ProtocolAddress } from '@unknownncat/swt-libsignal'

const a = new ProtocolAddress('alice', 1)
const encoded = a.toString()
const b = ProtocolAddress.from(encoded)
const same = a.equals(b)
```

Explicação: o exemplo cobre construção, serialização, parse e comparação de igualdade.

## Regras

- `id` não pode ser vazio nem conter `.`
- `deviceId` deve ser inteiro seguro e não negativo

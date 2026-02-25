# Fingerprint de identidade

`FingerprintGenerator` gera string comparável por humanos para validação fora de banda.

## Exemplo

```ts
import { FingerprintGenerator } from '@unknownncat/swt-libsignal'

const fp = new FingerprintGenerator(100)
const aliceKey = new Uint8Array(32).fill(11)
const bobKey = new Uint8Array(32).fill(22)

const value = fp.createFor('alice', aliceKey, 'bob', bobKey)
console.log(value)
```

## Recomendação

Use fingerprint em tela/QR + confirmação do usuário para evitar MITM.

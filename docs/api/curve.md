# Curve e identidade

## APIs

- `initCrypto`
- `signalCrypto.generateIdentityKeyPair`
- `signalCrypto.generateDHKeyPair`
- `signalCrypto.sign` e `signalCrypto.verify`
- `signalCrypto.calculateAgreement`
- Conversões Ed25519 -> X25519 via `convertIdentityPublicToX25519` e `convertIdentityPrivateToX25519`

## Exemplo

```ts
import { initCrypto, signalCrypto } from '@unknownncat/swt-libsignal'

await initCrypto()

const identity = await signalCrypto.generateIdentityKeyPair()
const dhA = await signalCrypto.generateDHKeyPair()
const dhB = await signalCrypto.generateDHKeyPair()

const sharedA = signalCrypto.calculateAgreement(dhB.publicKey, dhA.privateKey)
const sharedB = signalCrypto.calculateAgreement(dhA.publicKey, dhB.privateKey)

const msg = new TextEncoder().encode('signed prekey')
const signature = signalCrypto.sign(identity.privateKey, msg)
const valid = signalCrypto.verify(identity.publicKey, msg, signature)
```

Explicação: o exemplo valida assinatura Ed25519 e acordo de chave X25519 na mesma sessão de runtime.

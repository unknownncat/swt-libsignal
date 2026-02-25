# Curve e identidade (Ed25519/X25519)

## APIs

- `initCrypto()`: inicializa `libsodium`.
- `signalCrypto.generateIdentityKeyPair()`: par Ed25519.
- `signalCrypto.generateDHKeyPair()`: par X25519.
- `signalCrypto.sign/verify`.
- `signalCrypto.calculateAgreement`.
- `signalCrypto.convertIdentityPublicToX25519` e `convertIdentityPrivateToX25519`.
- `generateKeyPair`, `calculateSignature` (atalhos públicos).

## Exemplo prático

```ts
import { initCrypto, signalCrypto } from '@unknownncat/swt-libsignal'

await initCrypto()

const identity = await signalCrypto.generateIdentityKeyPair()
const dhA = await signalCrypto.generateDHKeyPair()
const dhB = await signalCrypto.generateDHKeyPair()

const sharedA = signalCrypto.calculateAgreement(dhB.publicKey, dhA.privateKey)
const sharedB = signalCrypto.calculateAgreement(dhA.publicKey, dhB.privateKey)

const msg = new TextEncoder().encode('signed prekey')
const sig = signalCrypto.sign(identity.privateKey, msg)
const ok = signalCrypto.verify(identity.publicKey, msg, sig)

console.log(sharedA.length, sharedB.length, ok)
```

## Segurança

- Sempre valide assinatura do signed prekey com a identidade pública esperada.
- Nunca aceite troca de identidade silenciosa em produção.

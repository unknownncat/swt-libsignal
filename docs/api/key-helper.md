# Key helper

Funções utilitárias para setup de conta/dispositivo.

## APIs

- `generateIdentityKeyPair` / `generateIdentityKeyPairAsync`
- `generateRegistrationId` / `generateRegistrationIdAsync`
- `generateSignedPreKey` / `generateSignedPreKeyAsync`
- `generatePreKey` / `generatePreKeyAsync`

## Exemplo

```ts
import {
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
} from '@unknownncat/swt-libsignal'

const identity = await generateIdentityKeyPair()
const registrationId = generateRegistrationId()
const signedPreKey = await generateSignedPreKey(identity, 1)
const oneTimePreKey = await generatePreKey(1)

console.log(registrationId, signedPreKey.keyId, oneTimePreKey.keyId)
```

## Segurança

- Guarde chaves privadas em armazenamento seguro.
- Rotacione prekeys periodicamente.

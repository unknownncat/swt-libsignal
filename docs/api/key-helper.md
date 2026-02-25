# Key helper

Utilitários para bootstrap de identidade e prekeys.

## APIs

- `generateIdentityKeyPair` e `generateIdentityKeyPairAsync`
- `generateRegistrationId` e `generateRegistrationIdAsync`
- `generateSignedPreKey` e `generateSignedPreKeyAsync`
- `generatePreKey` e `generatePreKeyAsync`

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
```

Explicação: o fluxo gera material mínimo para iniciar uma sessão X3DH.

# Crypto

## Superfícies

- `crypto` para operações síncronas.
- `cryptoAsync` para operações assíncronas.
- `createSignalSync` e `createSignalAsync` para fachada sync/async em APIs unificadas.

## Exemplo síncrono

```ts
import { crypto } from '@unknownncat/swt-libsignal'

const key = new Uint8Array(32).fill(1)
const iv = new Uint8Array(12).fill(2)
const aad = new TextEncoder().encode('meta')
const plaintext = new TextEncoder().encode('mensagem')

const sealed = crypto.encrypt(key, plaintext, { iv, aad })
const opened = crypto.decrypt(key, sealed, { aad })
```

Explicação: o bloco usa AES-256-GCM da API síncrona com AAD autenticado.

## Exemplo assíncrono

```ts
import { cryptoAsync } from '@unknownncat/swt-libsignal'

const key = new Uint8Array(32).fill(3)
const payload = new TextEncoder().encode('async')

const encrypted = await cryptoAsync.encrypt(key, payload)
const decrypted = await cryptoAsync.decrypt(key, encrypted)
const digest = await cryptoAsync.sha512(payload)
```

Explicação: a API assíncrona preserva os mesmos formatos de entrada e saída da versão síncrona.

## Boas práticas

- Não reutilizar o par `(key, iv)` no AES-GCM.
- Incluir metadados críticos em `aad`.
- Limpar buffers sensíveis após uso quando aplicável.

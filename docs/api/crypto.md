# Crypto (síncrono e assíncrono)

## O que existe

- `crypto.encrypt/decrypt`: AES-256-GCM síncrono.
- `crypto.sha512`, `crypto.hmacSha256`, `crypto.hkdf`.
- `cryptoAsync.*`: mesmas operações com WebCrypto async.
- `createSignalSync/createSignalAsync`: façade sync/async (async com worker threads).

## Exemplo síncrono

```ts
import { crypto } from '@unknownncat/swt-libsignal'

const key = new Uint8Array(32).fill(1)
const iv = new Uint8Array(12).fill(2)
const aad = new TextEncoder().encode('meta')
const plaintext = new TextEncoder().encode('mensagem')

const sealed = crypto.encrypt(key, plaintext, { iv, aad })
const opened = crypto.decrypt(key, sealed, { aad })

console.log(new TextDecoder().decode(opened))
```

## Exemplo assíncrono

```ts
import { cryptoAsync } from '@unknownncat/swt-libsignal'

const key = new Uint8Array(32).fill(3)
const payload = new TextEncoder().encode('async ok')

const encrypted = await cryptoAsync.encrypt(key, payload)
const decrypted = await cryptoAsync.decrypt(key, encrypted)
const digest = await cryptoAsync.sha512(payload)

console.log(decrypted.length, digest.length)
```

## Boas práticas

- Nunca reutilize `(key, iv)` no AES-GCM.
- Use `aad` para metadados autenticados (ex.: tipo da mensagem).
- Limpe buffers sensíveis após uso quando possível.

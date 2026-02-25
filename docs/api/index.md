# API do swt-libsignal

Este índice organiza a API pública por assunto.

## Primeiros passos

1. Use `ProtocolAddress` para endereçar pares.
2. Gere identidade, prekeys e signed prekey.
3. Configure storage com `createSessionStorage`.
4. Use `SessionBuilder` + `SessionCipher` para sessão e mensagens.

## Referência por arquivo

- [crypto.md](./crypto.md): AES-GCM, SHA-512, HMAC-SHA256, HKDF (sync/async).
- [curve.md](./curve.md): identidades Ed25519, DH X25519, assinatura/verificação.
- [fingerprint.md](./fingerprint.md): comparação de identidade humana.
- [job-queue.md](./job-queue.md): fila serial por bucket.
- [key-helper.md](./key-helper.md): geração de identidade, registration ID, prekeys.
- [protocol-address.md](./protocol-address.md): parse e serialização de endereço.
- [protobuf.md](./protobuf.md): encode/decode de mensagens protobuf.
- [ratchet-types.md](./ratchet-types.md): enums usados no estado de sessão.
- [signal-errors.md](./signal-errors.md): hierarquia de erros públicos.
- [sync-vs-async.md](./sync-vs-async.md): quando usar cada API.
- [session/index.md](./session/index.md): sessão ponta-a-ponta.
- [session/storage-adapter.md](./session/storage-adapter.md): adapters e persistência.
- [npm-scripts.md](./npm-scripts.md): scripts de build/teste/benchmark.
- [public-contract.md](./public-contract.md): snapshot/exportações públicas.
- [versioning-policy.md](./versioning-policy.md): compatibilidade e mudanças.

## Aviso rápido

Mesmo com API estável, a biblioteca deve ser tratada como **não pronta para produção**.

# libsignal compatibility layer

O projeto inclui uma camada compatível com contratos usados no ecossistema `libsignal-node`.

## Entrypoints

- `@unknownncat/swt-libsignal/libsignal`
- `@unknownncat/swt-libsignal/src/crypto`
- `@unknownncat/swt-libsignal/src/curve`
- `@unknownncat/swt-libsignal/src/protobufs`
- `@unknownncat/swt-libsignal/src/keyhelper`

## Objetivo

Permitir integração progressiva com código que espera:

- `ProtocolAddress`
- `SessionBuilder`
- `SessionCipher`
- `SessionRecord`
- helpers de `src/crypto`, `src/curve` e `src/protobufs`

## Validação

A interoperabilidade é validada em `test/integration/libsignal-node-interop.test.ts`
com troca bidirecional de mensagens e stress loop.


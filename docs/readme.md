# swt-libsignal — documentação simples e prática

> **Status do projeto:** biblioteca em evolução, com foco didático e de compatibilidade de API. **Não recomendada para produção**.

Este diretório reúne a documentação da biblioteca `@unknownncat/swt-libsignal` de forma direta, com exemplos executáveis.

## O que você encontra aqui

- Guia rápido de uso e visão geral.
- Referência de APIs públicas e tipos.
- Fluxos de sessão e storage.
- Criptografia síncrona e assíncrona.
- Protobuf, serialização e utilitários.
- Scripts de manutenção e contrato público.

## Instalação e requisitos

Node.js `20.x` (LTS) ou `>= 22`

- TypeScript (opcional, mas recomendado)

```bash
npm install @unknownncat/swt-libsignal
```

## Exemplo rápido (criptografia síncrona)

```ts
import { crypto } from "@unknownncat/swt-libsignal";

const key = new Uint8Array(32).fill(7);
const message = new TextEncoder().encode("hello");

const encrypted = crypto.encrypt(key, message);
const decrypted = crypto.decrypt(key, encrypted);

console.log(new TextDecoder().decode(decrypted)); // hello
```

## Avisos de segurança (leia antes de integrar)

- **Validação de identidade:** sempre valide chave de identidade remota (fingerprint, PIN compartilhado, QR etc.) antes de confiar em sessão.
- **Assinatura de signed prekey:** valide a assinatura do signed prekey com a identidade do par antes de aceitar material de sessão.

## Índice da documentação

- [API geral](./api/index.md)
- [Exemplos](./examples/public-api.ts)

## Escopo coberto

A documentação em `docs/api` cobre módulos públicos, sessões, storage, tipos de ratchet, protobuf, curva/assinatura, utilitários assíncronos/síncronos e scripts do projeto.

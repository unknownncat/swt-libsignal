# swt-libsignal docs

> Status: biblioteca em evolução com foco didático e de compatibilidade de API. Não recomendada para produção sem hardening adicional.

Este diretório documenta as APIs públicas e inclui scripts executáveis em `docs/examples` para validar fluxos reais da biblioteca.

## Requisitos

- Node.js `>=20`
- TypeScript opcional

## Instalação

```bash
npm install @unknownncat/swt-libsignal
```

Explicação: instala a biblioteca publicada no npm.

## Exemplo rápido

```ts
import { crypto } from "@unknownncat/swt-libsignal";

const key = new Uint8Array(32).fill(7);
const message = new TextEncoder().encode("hello");

const encrypted = crypto.encrypt(key, message);
const decrypted = crypto.decrypt(key, encrypted);

console.log(new TextDecoder().decode(decrypted));
```

Explicação: usa AES-256-GCM da API `crypto` para cifrar e decifrar no mesmo processo.

## Exemplos executáveis

- [run-all.ts](./examples/run-all.ts)
- [crypto-runtime-check.ts](./examples/crypto-runtime-check.ts)
- [session-runtime-check.ts](./examples/session-runtime-check.ts)
- [group-runtime-check.ts](./examples/group-runtime-check.ts)
- [repository-runtime-check.ts](./examples/repository-runtime-check.ts)
- [storage-runtime-check.ts](./examples/storage-runtime-check.ts)
- [production-readiness-runtime-check.ts](./examples/production-readiness-runtime-check.ts)

Os scripts acima são executados na suíte de testes para garantir que os exemplos documentados continuem válidos.

## Segurança e hardening

- [Threat model](./security/threat-model.md)
- [Security validation](./security/validation.md)
- Política de reporte: [`SECURITY.md`](../SECURITY.md)

Este projeto inclui validação contínua para:

- interoperabilidade com `libsignal-node` (`npm run test:interop`)
- fuzz/property tests (`npm run test:fuzz`)
- pipelines de segurança e supply-chain em `.github/workflows`

## Índice da API

- [API geral](./api/index.md)

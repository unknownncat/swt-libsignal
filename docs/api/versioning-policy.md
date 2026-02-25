# Política de versionamento

## Princípios

- APIs documentadas em `src/public/*` são contrato principal.
- Mudanças em nomes/exportações públicas devem atualizar:
  - `docs/api/public-exports.snapshot.json`
  - `docs/api/public-contract.md`
- Correções internas sem quebra podem sair em minor/patch.

## Para mantenedores

Sempre execute:

```bash
npm run test:exports
```

Se mudou API de propósito:

```bash
npm run test:exports:update
```

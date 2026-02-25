# Scripts npm do projeto

## Principais comandos

- `npm run build`: compila TypeScript.
- `npm run test`: roda suíte Vitest.
- `npm run lint`: type-check sem emitir arquivos.
- `npm run test:exports`: valida snapshot de exportações públicas.
- `npm run benchmark`: benchmark da job queue.
- `npm run proto:gen`: regenera arquivos protobuf.

## Fluxo recomendado para contribuição

```bash
npm run lint
npm run test
npm run test:exports
npm run build
```

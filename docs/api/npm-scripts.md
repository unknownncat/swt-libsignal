# Scripts npm do projeto

## Principais comandos

- `npm run build`: compila TypeScript.
- `npm run test`: roda suíte Vitest.
- `npm run test:interop`: valida interoperabilidade contra `libsignal-node`.
- `npm run test:fuzz`: executa fuzz/property tests do protocolo.
- `npm run lint`: type-check sem emitir arquivos.
- `npm run security:audit`: audit de dependências com threshold alto.
- `npm run test:exports`: valida snapshot de exportações públicas.
- `npm run benchmark`: benchmark da job queue.
- `npm run examples:run`: executa todos os runtime-checks de `docs/examples`.
- `npm run proto:gen`: regenera arquivos protobuf.

## Fluxo recomendado para contribuição

```bash
npm run lint
npm run test
npm run test:interop
npm run test:exports
npm run build
```

Explicação: esse fluxo confirma tipos, regressões, interoperabilidade, contrato público e build final antes de publicar mudanças.

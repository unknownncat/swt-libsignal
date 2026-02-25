# SessionBuilder

`SessionBuilder` cria sessão de saída (`initOutgoing`) e sessão de entrada (`initIncoming`).

## API

```ts
class SessionBuilder {
  constructor(storage: SessionBuilderStorage, protocolAddress: ProtocolAddress, options?: SessionBuilderOptions)
  initOutgoing(device: PreKeyBundle): Promise<void>
  initIncoming(record: SessionRecord, message: PreKeyWhisperMessage): Promise<number | undefined>
}
```

Explicação: `initOutgoing` prepara uma sessão iniciadora e `initIncoming` usa prekeys locais para aceitar a primeira mensagem do par.

## Fluxo essencial

1. Validar identidade e assinatura de signed prekey.
2. Derivar segredos iniciais do handshake.
3. Criar `SessionEntry` inicial.
4. Persistir sessão.

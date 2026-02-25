# SessionCipher

`SessionCipher` executa encrypt/decrypt e manutenção do estado Double Ratchet.

## API

```ts
class SessionCipher {
  constructor(storage: SessionCipherStorage, protocolAddress: ProtocolAddress, options?: SessionCipherOptions)
  encrypt(data: Uint8Array): Promise<EncryptResult>
  decryptWhisperMessage(data: Uint8Array): Promise<Uint8Array>
  decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Uint8Array>
  hasOpenSession(): Promise<boolean>
  closeOpenSession(): Promise<void>
}
```

Explicação: `encrypt` produz mensagens `type=1` ou `type=3` e as funções de decrypt escolhem o envelope correto.

## Comportamento relevante atual

- O `cryptoSuite` padrão é `CbcHmacSuite`.
- Decrypt é transacional para evitar mutação de estado em falha.
- Há orçamento de `messageKeys` por chain/sessão para conter crescimento de memória.

## Erros comuns

- `SessionError`
- `SessionDecryptFailed`
- `SessionStateError`
- `MessageCounterError`
- `UntrustedIdentityKeyError`

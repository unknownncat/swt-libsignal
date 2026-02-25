# Erros públicos

Hierarquia principal:

- `SignalError`
- `UntrustedIdentityKeyError`
- `SessionError`
- `SessionStateError`
- `SessionDecryptFailed`
- `MessageCounterError`
- `PreKeyError`
- `ProtobufValidationError`

## Exemplo de tratamento

```ts
import { SignalError, SessionDecryptFailed } from '@unknownncat/swt-libsignal'

try {
  throw new SessionDecryptFailed('falha no decrypt')
} catch (err) {
  if (err instanceof SessionDecryptFailed) {
    console.log('mensagem inválida')
  } else if (err instanceof SignalError) {
    console.log('erro signal genérico')
  }
}
```

Explicação: a hierarquia de erros permite tratar falhas criptográficas específicas sem perder o fallback genérico.

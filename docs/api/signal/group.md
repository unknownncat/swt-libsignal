# Signal group

O namespace `signal/group` implementa Sender Keys para mensagens de grupo:

- `GroupSessionBuilder`
- `GroupCipher`
- `SenderKeyRecord` e estados auxiliares
- `SenderKeyMessage` e `SenderKeyDistributionMessage`

## Exemplo

```ts
import {
  GroupCipher,
  GroupSessionBuilder,
  SenderKeyDistributionMessage,
  SenderKeyName,
} from '@unknownncat/swt-libsignal'

const senderName = new SenderKeyName('group-id', senderAddress)
const distribution = await builder.create(senderName)

await receiverBuilder.process(
  senderName,
  new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, distribution.serialize())
)

const ciphertext = await senderCipher.encrypt(new TextEncoder().encode('group-message'))
const plaintext = await receiverCipher.decrypt(ciphertext)
```

Explicação: `create` gera o material inicial de Sender Key, `process` instala no receptor e `GroupCipher` faz encrypt/decrypt com rotação por iteração.

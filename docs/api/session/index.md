# Sessões

Este módulo concentra criação, manutenção e uso de sessão criptográfica.

## Componentes

- `SessionBuilder`: inicializa sessão de saída/entrada.
- `SessionCipher`: cifra/decifra mensagens.
- `SessionRecord` e `SessionEntry`: estado serializável da sessão.

## Exemplo simples de estado de sessão (serialização)

```ts
import { SessionRecord, SessionEntry, BaseKeyType } from '@unknownncat/swt-libsignal'

const entry = new SessionEntry()
entry.registrationId = 1234
entry.currentRatchet = {
  ephemeralKeyPair: { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
  lastRemoteEphemeralKey: new Uint8Array(32).fill(3),
  previousCounter: 0,
  rootKey: new Uint8Array(32).fill(4),
}
entry.indexInfo = {
  baseKey: new Uint8Array(32).fill(5),
  baseKeyType: BaseKeyType.THEIRS,
  closed: -1,
  used: 1,
  created: 1,
  remoteIdentityKey: new Uint8Array(32).fill(6),
}

const record = new SessionRecord()
record.setSession(entry)

const serialized = record.serialize()
const restored = SessionRecord.deserialize(serialized)

console.log(restored.getSessions().length)
```

## Fluxo resumido real

1. Gere identidade + prekeys.
2. Monte `PreKeyBundle` remoto.
3. `SessionBuilder.initOutgoing(bundle)`.
4. Use `SessionCipher.encrypt/decrypt*`.
5. Persista `SessionRecord` no storage.

## Segurança

- Em troca de identidade, trate divergência como potencial ataque.
- Feche sessão (`closeOpenSession`) quando necessário para rotação.

# Sessões 1:1

Módulos centrais:

- `SessionBuilder`
- `SessionCipher`
- `SessionRecord` e `SessionEntry`

## Exemplo de estado serializável

```ts
import { BaseKeyType, SessionEntry, SessionRecord } from '@unknownncat/swt-libsignal'

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
const restored = SessionRecord.deserialize(record.serialize())
```

Explicação: o estado de sessão é serializado para persistência e restaurado sem perda de estrutura.

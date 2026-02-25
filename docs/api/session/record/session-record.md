# SessionRecord e SessionEntry

`SessionRecord` é o container de sessões e `SessionEntry` representa um estado individual.

## Funções principais

- Registrar e recuperar sessões por base key.
- Ordenar por último uso para acelerar decrypt.
- Serializar e desserializar estado completo de ratchet e chains.

## Exemplo

```ts
import { SessionRecord } from '@unknownncat/swt-libsignal'

const record = new SessionRecord()
const encoded = record.serialize()
const restored = SessionRecord.deserialize(encoded)
```

Explicação: `serialize` converte o estado em objeto persistível e `deserialize` reconstrói estruturas internas.

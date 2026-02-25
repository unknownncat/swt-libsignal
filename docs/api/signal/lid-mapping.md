# LIDMappingStore

`LIDMappingStore` mantém mapeamentos entre identificadores PN e LID.

## APIs principais

- `storeLIDPNMappings`
- `getLIDForPN`
- `getLIDsForPNs`
- `getPNForLID`
- `getPNsForLIDs`

## Exemplo

```ts
import { LIDMappingStore } from '@unknownncat/swt-libsignal'

const store = new LIDMappingStore()
await store.storeLIDPNMappings([{ pn: '5511912345678@s.whatsapp.net', lid: '123456@lid' }])

const lid = await store.getLIDForPN('5511912345678@s.whatsapp.net')
```

Explicação: o store suporta cache em memória e backend opcional para persistência via `LIDMappingKeyStore`.

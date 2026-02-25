# Protobuf e serialização de mensagens

A biblioteca expõe codecs prontos:

- `WhisperMessageCodec`
- `PreKeyWhisperMessageCodec`

## Exemplo

```ts
import { WhisperMessageCodec, PreKeyWhisperMessageCodec } from '@unknownncat/swt-libsignal'

const whisper = WhisperMessageCodec.encode({
  ephemeralKey: new Uint8Array(32).fill(1),
  counter: 1,
  previousCounter: 0,
  ciphertext: new Uint8Array([10, 20, 30]),
})

const decodedWhisper = WhisperMessageCodec.decode(whisper)

const preKey = PreKeyWhisperMessageCodec.encode({
  registrationId: 7,
  preKeyId: 3,
  signedPreKeyId: 9,
  baseKey: new Uint8Array(32).fill(2),
  identityKey: new Uint8Array(32).fill(3),
  message: whisper,
})

const decodedPreKey = PreKeyWhisperMessageCodec.decode(preKey)
console.log(decodedWhisper.counter, decodedPreKey.registrationId)
```

Explicação: os codecs preservam campos do envelope Whisper/PreKey para transporte e parsing determinístico.

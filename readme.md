# swt-libsignal

> ⚠️ **Aviso Importante:** Este projeto foi desenvolvido apenas para fins de estudo e aprendizado.  
> ❌ **Não recomendado** para uso em projetos de grande porte, ambientes de produção ou sistemas críticos.

---

O **swt-libsignal** é uma implementação educacional inspirada no ecossistema Signal, cobrindo criptografia simétrica e assimétrica (AES-256-GCM, HKDF-SHA256, Ed25519, X25519).  
Ele inclui handshake/sessão baseado em X3DH adaptado e Double Ratchet, além de serialização de mensagens via Protobuf em formato “Signal-like”.

O projeto oferece:

- Camadas de storage síncrono e assíncrono.
- API pública dual (**SignalSyncAPI** e **SignalAsyncAPI**).
- Suporte opcional a workers.
- Controles de concorrência por fila (enqueue).
- Boas práticas de segurança: validação de identidade, assinatura de signed prekey e descarte de chaves.
- Camada de compatibilidade `libsignal` (`/libsignal` e subpaths `/src/*`).
- Interoperabilidade validada com `WhiskeySockets/libsignal-node`.
- Adapter SQLite assíncrono com transação (`SqliteAsyncStorageAdapter`).
- Fuzz/property tests de protocolo e CI de segurança/supply-chain.

A documentação completa está disponível na pasta [docs](https://github.com/unknownncat/swt-libsignal/blob/main/docs).

Este é um projeto que venho desenvolvendo há algum tempo e quero compartilhar com vocês.

### inspirado em [libsignal-node](https://github.com/WhiskeySockets/libsignal-node) de [WhiskeySockets](https://github.com/WhiskeySockets)

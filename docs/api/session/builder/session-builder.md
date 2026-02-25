# `SessionBuilder`

## O que ele faz

O `SessionBuilder` é responsável por **criar e inicializar sessões seguras** no estilo Signal.

Ele atua em dois cenários:

* **`initOutgoing`** → quando você quer iniciar uma sessão com base em um `PreKeyBundle` remoto.
* **`initIncoming`** → quando você recebe uma mensagem `PreKeyWhisperMessage` e precisa criar a sessão como respondedor.

Ele prepara o estado inicial que depois será usado pelo `SessionCipher`.

---

## API Pública

```ts
class SessionBuilder {
  constructor(storage: SessionBuilderStorage, protocolAddress: ProtocolAddress);
  initOutgoing(device: PreKeyBundle): Promise<void>;
  initIncoming(record: SessionRecord, message: PreKeyWhisperMessage): Promise<number | undefined>;
}
```

### Métodos

* **constructor** → recebe o storage e o endereço do protocolo.
* **initOutgoing** → cria sessão iniciadora.
* **initIncoming** → cria sessão como respondedor e retorna o `preKeyId` consumido (se houver).

---

## Fluxo do `initOutgoing` (quem inicia a conversa)

1. Valida se o `PreKeyBundle` possui todos os campos obrigatórios.
2. Verifica se a identidade remota é confiável.
3. Valida a assinatura da signed prekey remota.
4. Executa a derivação de chaves (handshake tipo X3DH).
5. Cria a sessão inicial (`initSession`).
6. Define `pendingPreKey` (necessário para a primeira mensagem).
7. Fecha sessão anterior (se existir).
8. Persiste a nova sessão no storage.

### Resultado

Uma nova sessão pronta para enviar a primeira mensagem (`type=3`).

---

## Fluxo do `initIncoming` (quem recebe a primeira mensagem)

1. Verifica se a identidade do remetente é confiável.
2. Evita recriar sessão se a `baseKey` já estiver registrada.
3. Carrega:

   * PreKey local
   * Signed PreKey local
4. Executa derivação de sessão no modo respondedor.
5. Registra sessão no `SessionRecord`.
6. Retorna o `preKeyId` que deve ser removido (se aplicável).

### Resultado

Sessão criada e pronta para descriptografar mensagens futuras.

---

## Exemplo de uso

```ts
import { ProtocolAddress, SessionBuilder, SessionRecord, type SessionBuilderStorage } from '@unknownncat/swt-libsignal';

const storage: SessionBuilderStorage = {
  isTrustedIdentity: async () => true,
  loadSession: async () => undefined,
  storeSession: async () => undefined,
  getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(64) }),
  loadPreKey: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(32) }),
  loadSignedPreKey: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(32) })
};

const builder = new SessionBuilder(storage, new ProtocolAddress('bob', 1));
const record = new SessionRecord();
```

---

## Erros Possíveis

| Situação                             | Erro                        |
| ------------------------------------ | --------------------------- |
| Assinatura da signed prekey inválida | Erro de segurança           |
| PreKey inexistente no modo incoming  | `PreKeyError`               |
| Identidade não confiável             | `UntrustedIdentityKeyError` |

---

## Casos Especiais (Edge Cases)

* Se a `baseKey` já foi usada → sessão não é recriada.
* Se prekey já foi consumida → erro.
* Se identidade falhar na validação → sessão não é criada.

---

## Limitações Atuais

* A API não informa detalhadamente em qual etapa do handshake ocorreu falha.
* Não há métricas de tempo ou rastreamento do caminho criptográfico usado.

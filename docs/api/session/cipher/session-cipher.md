# `SessionCipher`

## O que ele faz

O `SessionCipher` é responsável por:

* Criptografar mensagens.
* Descriptografar mensagens.
* Gerenciar o estado da sessão baseado no **Double Ratchet**.
* Validar se a identidade remota é confiável.
* Atualizar e persistir o estado da sessão com segurança.

Ele é o ponto principal de envio e recebimento de mensagens seguras.

---

## API Pública

```ts
class SessionCipher {
  constructor(storage: SessionCipherStorage, protocolAddress: ProtocolAddress);
  toString(): string;
  encrypt(data: Uint8Array): Promise<EncryptResult>;
  decryptWhisperMessage(data: Uint8Array): Promise<Uint8Array>;
  decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Uint8Array>;
  hasOpenSession(): Promise<boolean>;
  closeOpenSession(): Promise<void>;
}
```

### Métodos

* **constructor** → recebe o storage e o endereço do protocolo.
* **encrypt** → criptografa uma mensagem.
* **decryptWhisperMessage** → descriptografa mensagem normal (type=1).
* **decryptPreKeyWhisperMessage** → descriptografa mensagem inicial (type=3).
* **hasOpenSession** → verifica se existe sessão aberta.
* **closeOpenSession** → encerra sessão ativa.

---

## Como o Encrypt funciona (passo a passo)

1. Verifica se existe uma sessão aberta.
2. Carrega o `SessionRecord` do storage.
3. Valida se a identidade remota é confiável.
4. Deriva a **message key** a partir da chain key.
5. Criptografa usando AES-GCM + MAC.
6. Persiste o novo estado da sessão.
7. Remove a message key (mesmo se ocorrer erro).

### Tipo da mensagem enviada

* `type = 3` → quando existe `pendingPreKey` (primeira mensagem da sessão).
* `type = 1` → mensagens normais após sessão estabelecida.

---

## Como o Decrypt Whisper funciona

1. Tenta descriptografar usando as sessões disponíveis (ordem de uso).
2. Se receber nova chave efêmera → executa ratchet step.
3. Valida MAC.
4. Descriptografa o conteúdo.
5. Remove a message key usada.
6. Persiste o estado atualizado.

Se todas as sessões falharem, lança erro agregado.

---

## Como o Decrypt PreKey Whisper funciona

1. Valida versão e campos obrigatórios.
2. Cria sessão incoming usando `SessionBuilder`.
3. Descriptografa a mensagem interna.
4. Persiste sessão e remove prekey:

   * Se existir `storeSessionAndRemovePreKey` → operação atômica.
   * Caso contrário → executa `storeSession` e depois `removePreKey`.

---

## Exemplo de uso

```ts
import { ProtocolAddress, SessionCipher, type SessionCipherStorage } from '@unknownncat/swt-libsignal';

const storage: SessionCipherStorage = {
  loadSession: async () => undefined,
  storeSession: async () => undefined,
  getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(64) }),
  isTrustedIdentity: async () => true,
  getOurRegistrationId: async () => 1,
  loadPreKey: async () => undefined,
  loadSignedPreKey: async () => undefined,
  removePreKey: async () => undefined
};

const cipher = new SessionCipher(storage, new ProtocolAddress('alice', 1));
```

---

## Possíveis Erros

| Situação                          | Erro lançado                                      |
| --------------------------------- | ------------------------------------------------- |
| Sem sessão aberta                 | `SessionError`                                    |
| Estado inválido de chain/ratchet  | `SessionStateError` (`SESSION_STATE_ERROR`)       |
| Falha ao tentar múltiplas sessões | `SessionDecryptFailed` (`SESSION_DECRYPT_FAILED`) |
| Identidade não confiável          | `UntrustedIdentityKeyError`                       |
| Reuso ou contador inválido        | `MessageCounterError`                             |
| Versão incompatível               | `Error`                                           |

---

## Complexidade

* **Derivação de chave:** O(Δcontador)
* **Tentativa entre sessões:** O(n)
* **Memória:** mapa de `messageKeys` por chain (limitado pela política de avanço)

---

## Casos especiais (Edge Cases)

* Mensagens muito à frente (>2000) → rejeitadas.
* Counter próximo de `MAX_SAFE_INTEGER` → rejeitado.
* Chains fechadas (`chainKey.key === undefined`) → não derivam novas chaves.

---

## Limitação Atual

* A verificação de MAC usa `timingSafeEqual` com buffers normalizados e tamanho fixo de truncamento.

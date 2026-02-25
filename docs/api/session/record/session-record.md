# `SessionRecord` e `SessionEntry`

## O que eles fazem

Essas duas estruturas representam **o estado persistente das sessões**.

Elas armazenam:

* Estado atual do ratchet
* Chains (envio e recebimento)
* Message keys derivadas
* Metadados de uso
* Informações de prekey pendente

São o núcleo do estado que será salvo no storage.

---

## Estruturas Principais

### `SessionRecord`

* Coleção de sessões.
* Indexada pela **base key**.
* Responsável por:

  * Adicionar sessões
  * Recuperar sessões
  * Ordenar por uso
  * Serializar / desserializar
  * Remover sessões antigas

### `SessionEntry`

Representa **uma sessão individual**.

Contém:

* `registrationId`
* `currentRatchet`
* `indexInfo`
* `pendingPreKey` (opcional)
* Conjunto de chains (envio e recebimento)

---

## Componentes Associados

* `ChainState`
* `ChainKey`
* `CurrentRatchet`
* `IndexInfo`
* Tipos `Serialized*` usados para persistência

---

## Como funciona internamente

### 1️⃣ Adicionando sessão

* `SessionRecord.setSession` registra uma nova `SessionEntry`.
* Cada sessão é indexada pela base key.

---

### 2️⃣ Recuperando sessões

* `getSessions()` retorna lista ordenada.
* A ordenação usa `indexInfo.used`.
* Sessões mais recentemente usadas vêm primeiro.

Isso melhora performance no decrypt (primeira tentativa geralmente funciona).

---

### 3️⃣ Serialização

Ao salvar:

* `Uint8Array` → convertido para base64.
* Chains e message keys → convertidas para formato serializável.
* Resultado → objeto puro JSON.

---

### 4️⃣ Desserialização

Ao restaurar:

* Base64 → reconvertido para `Uint8Array`.
* Maps de chains reconstruídos.
* Message keys restauradas corretamente.

---

## Exemplo

```ts id="k9l2xw"
import { SessionRecord } from '@unknownncat/swt-libsignal';

const record = new SessionRecord();

// Serializa
const encoded = record.serialize();

// Restaura
const restored = SessionRecord.deserialize(encoded);
```

---

## Fluxo Resumido

1. Sessão criada pelo `SessionBuilder`.
2. Registrada no `SessionRecord`.
3. `SessionCipher` atualiza chains e ratchet.
4. Estado é serializado e persistido.
5. Na próxima execução, é desserializado.

---

## Casos Especiais (Edge Cases)

* `getSession` com base key local (`BaseKeyType.OURS`) → lança erro (proteção de integridade).
* `addChain` não permite sobrescrever chain existente.
* `deleteChain` lança `ReferenceError` se a chain não existir.

---

## Limitações Atuais

* Limite fixo de sessões fechadas:

  ```
  CLOSED_SESSIONS_MAX = 40
  ```
* Cache interno de ordenação é simples.
* Não é thread-safe (adequado ao modelo single-thread do JavaScript).

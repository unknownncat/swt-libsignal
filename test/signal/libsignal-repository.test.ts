import { describe, expect, it } from 'vitest'
import { initCrypto, signalCrypto } from '../../src/curve'
import { createSessionStorage, InMemoryStorage } from '../../src/session/storage'
import { generatePreKey, generateRegistrationId, generateSignedPreKey } from '../../src/key-helper'
import { makeLibSignalRepository } from '../../src/signal/libsignal'
import { SenderKeyName, SenderKeyRecord } from '../../src/signal/group'

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

function createRepositoryStore() {
  const adapter = new InMemoryStorage<unknown>()
  const sessionStore = createSessionStorage(adapter)

  const store = {
    ...sessionStore,
    async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord> {
      const raw = adapter.get(`sender-key:${senderKeyName.toString()}`) as Uint8Array | undefined
      return raw ? SenderKeyRecord.deserialize(raw) : new SenderKeyRecord()
    },
    async storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void> {
      adapter.set(`sender-key:${senderKeyName.toString()}`, record.serializeToBytes())
    },
    async deleteSession(addressName: string): Promise<void> {
      adapter.delete(`session:${addressName}`)
    },
    async saveIdentity(addressName: string, identityKey: Uint8Array): Promise<boolean> {
      const key = `identity:${addressName}`
      const existing = adapter.get(key) as Uint8Array | undefined
      if (!existing) {
        adapter.set(key, identityKey)
        return true
      }
      if (!constantTimeEqual(existing, identityKey)) {
        adapter.set(key, identityKey)
        adapter.delete(`session:${addressName}`)
        return true
      }
      return false
    },
    async transaction<T>(run: () => Promise<T>): Promise<T> {
      return run()
    },
  }

  return { adapter, store }
}

describe('signal repository compatibility layer', () => {
  it('supports 1:1 and group message flows', async () => {
    await initCrypto()

    const alice = createRepositoryStore()
    const bob = createRepositoryStore()

    const aliceIdentity = await signalCrypto.generateIdentityKeyPair()
    const bobIdentity = await signalCrypto.generateIdentityKeyPair()
    const aliceReg = generateRegistrationId()
    const bobReg = generateRegistrationId()

    await alice.store.storeBootstrap({ pubKey: aliceIdentity.publicKey, privKey: aliceIdentity.privateKey }, aliceReg)
    await bob.store.storeBootstrap({ pubKey: bobIdentity.publicKey, privKey: bobIdentity.privateKey }, bobReg)

    const bobSignedPreKey = await generateSignedPreKey(bobIdentity, 11)
    const bobPreKey = await generatePreKey(7)
    bob.adapter.set('signedprekey:11', { pubKey: bobSignedPreKey.keyPair.publicKey, privKey: bobSignedPreKey.keyPair.privateKey })
    bob.adapter.set('prekey:7', { pubKey: bobPreKey.keyPair.publicKey, privKey: bobPreKey.keyPair.privateKey })

    const aliceRepo = makeLibSignalRepository(alice.store)
    const bobRepo = makeLibSignalRepository(bob.store)

    await aliceRepo.injectE2ESession({
      jid: 'bob.1',
      session: {
        identityKey: bobIdentity.publicKey,
        registrationId: bobReg,
        preKey: { keyId: 7, publicKey: bobPreKey.keyPair.publicKey },
        signedPreKey: {
          keyId: 11,
          publicKey: bobSignedPreKey.keyPair.publicKey,
          signature: bobSignedPreKey.signature,
        },
      }
    })

    const encrypted = await aliceRepo.encryptMessage({
      jid: 'bob.1',
      data: new TextEncoder().encode('repo-hello'),
    })
    expect(encrypted.type).toBe('pkmsg')

    const decrypted = await bobRepo.decryptMessage({
      jid: 'alice.1',
      type: 'pkmsg',
      ciphertext: encrypted.ciphertext,
    })
    expect(decrypted).toEqual(new TextEncoder().encode('repo-hello'))

    const groupEncrypted = await aliceRepo.encryptGroupMessage({
      group: 'group-1',
      meId: 'alice.1',
      data: new TextEncoder().encode('group-hi'),
    })

    await bobRepo.processSenderKeyDistributionMessage({
      groupId: 'group-1',
      authorJid: 'alice.1',
      axolotlSenderKeyDistributionMessage: groupEncrypted.senderKeyDistributionMessage,
    })

    const groupDecrypted = await bobRepo.decryptGroupMessage({
      group: 'group-1',
      authorJid: 'alice.1',
      msg: groupEncrypted.ciphertext,
    })
    expect(groupDecrypted).toEqual(new TextEncoder().encode('group-hi'))
  })
})

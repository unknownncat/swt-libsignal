import { describe, expect, it } from 'vitest'
import { ProtocolAddress } from '../../src/protocol_address'
import { signalCrypto } from '../../src/curve'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { InMemoryStorage } from '../../src/session/storage/in-memory'
import { createSessionStorage } from '../../src/session/storage/adapter'
import { generatePreKey, generateRegistrationId, generateSignedPreKey } from '../../src/key-helper'

describe('session integration flow', () => {
  it('establishes outgoing/incoming sessions and exchanges encrypted messages', async () => {
    const aliceAdapter = new InMemoryStorage<unknown>()
    const bobAdapter = new InMemoryStorage<unknown>()
    const aliceStorage = createSessionStorage(aliceAdapter)
    const bobStorage = createSessionStorage(bobAdapter)

    const aliceIdentity = await signalCrypto.generateIdentityKeyPair()
    const bobIdentity = await signalCrypto.generateIdentityKeyPair()
    const bobSignIdentity = await signalCrypto.generateIdentityKeyPair()
    const aliceReg = generateRegistrationId()
    const bobReg = generateRegistrationId()

    await aliceStorage.storeBootstrap({ pubKey: aliceIdentity.publicKey, privKey: aliceIdentity.privateKey }, aliceReg)
    await bobStorage.storeBootstrap({ pubKey: bobIdentity.publicKey, privKey: bobIdentity.privateKey }, bobReg)

    const bobSignedPreKey = await generateSignedPreKey(bobSignIdentity, 11)
    const bobPreKey = await generatePreKey(7)

    bobAdapter.set('signedprekey:11', { pubKey: bobSignedPreKey.keyPair.publicKey, privKey: bobSignedPreKey.keyPair.privateKey })
    bobAdapter.set('prekey:7', { pubKey: bobPreKey.keyPair.publicKey, privKey: bobPreKey.keyPair.privateKey })

    const aliceToBob = new ProtocolAddress('bob', 1)
    const bobToAlice = new ProtocolAddress('alice', 1)

    const aliceBuilder = new SessionBuilder(aliceStorage, aliceToBob)
    await aliceBuilder.initOutgoing({
      identityKey: bobSignIdentity.publicKey,
      registrationId: bobReg,
      preKey: { keyId: 7, publicKey: bobPreKey.keyPair.publicKey },
      signedPreKey: {
        keyId: 11,
        publicKey: bobSignedPreKey.keyPair.publicKey,
        signature: bobSignedPreKey.signature,
      },
    })

    const aliceCipher = new SessionCipher(aliceStorage, aliceToBob)
    const bobCipher = new SessionCipher(bobStorage, bobToAlice)

    const first = await aliceCipher.encrypt(new TextEncoder().encode('hello bob'))
    expect(first.type).toBe(3)

    await expect(bobCipher.decryptPreKeyWhisperMessage(first.body)).rejects.toThrow('MAC verification failed')

    expect(await aliceCipher.hasOpenSession()).toBe(true)
    await aliceCipher.closeOpenSession()
    expect(await aliceCipher.hasOpenSession()).toBe(false)
  })
})

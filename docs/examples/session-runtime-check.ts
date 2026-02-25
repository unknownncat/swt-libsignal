import { initCrypto, signalCrypto } from '../../src/curve'
import { generatePreKey, generateRegistrationId, generateSignedPreKey } from '../../src/key-helper'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { createSessionStorage, InMemoryStorage } from '../../src/session/storage'

export interface SessionRuntimeCheckResult {
  readonly firstType: number
  readonly firstMessageOk: boolean
  readonly secondType: number
  readonly secondMessageOk: boolean
}

export async function runSessionRuntimeCheck(): Promise<SessionRuntimeCheckResult> {
  await initCrypto()

  const aliceAdapter = new InMemoryStorage<unknown>()
  const bobAdapter = new InMemoryStorage<unknown>()
  const aliceStorage = createSessionStorage(aliceAdapter)
  const bobStorage = createSessionStorage(bobAdapter)

  const aliceIdentity = await signalCrypto.generateIdentityKeyPair()
  const bobIdentity = await signalCrypto.generateIdentityKeyPair()
  const aliceReg = generateRegistrationId()
  const bobReg = generateRegistrationId()

  await aliceStorage.storeBootstrap({ pubKey: aliceIdentity.publicKey, privKey: aliceIdentity.privateKey }, aliceReg)
  await bobStorage.storeBootstrap({ pubKey: bobIdentity.publicKey, privKey: bobIdentity.privateKey }, bobReg)

  const bobSignedPreKey = await generateSignedPreKey(bobIdentity, 11)
  const bobPreKey = await generatePreKey(7)
  bobAdapter.set('signedprekey:11', { pubKey: bobSignedPreKey.keyPair.publicKey, privKey: bobSignedPreKey.keyPair.privateKey })
  bobAdapter.set('prekey:7', { pubKey: bobPreKey.keyPair.publicKey, privKey: bobPreKey.keyPair.privateKey })

  const aliceToBob = new ProtocolAddress('bob', 1)
  const bobToAlice = new ProtocolAddress('alice', 1)

  const aliceBuilder = new SessionBuilder(aliceStorage, aliceToBob)
  await aliceBuilder.initOutgoing({
    identityKey: bobIdentity.publicKey,
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

  const firstText = 'docs-session-first'
  const first = await aliceCipher.encrypt(new TextEncoder().encode(firstText))
  const firstPlain = await bobCipher.decryptPreKeyWhisperMessage(first.body)

  const secondText = 'docs-session-second'
  const second = await aliceCipher.encrypt(new TextEncoder().encode(secondText))
  const secondPlain = second.type === 3
    ? await bobCipher.decryptPreKeyWhisperMessage(second.body)
    : await bobCipher.decryptWhisperMessage(second.body)

  return {
    firstType: first.type,
    firstMessageOk: new TextDecoder().decode(firstPlain) === firstText,
    secondType: second.type,
    secondMessageOk: new TextDecoder().decode(secondPlain) === secondText,
  }
}

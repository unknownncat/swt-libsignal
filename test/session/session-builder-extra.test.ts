import { describe, expect, it } from 'vitest'
import { ProtocolAddress } from '../../src/protocol_address'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { SessionRecord } from '../../src/session/record'

describe('SessionBuilder validations and error paths', () => {
  const storage = {
    isTrustedIdentity: async () => true,
    loadSession: async () => undefined,
    storeSession: async () => undefined,
    getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(32) }),
    loadPreKey: async () => undefined,
    loadSignedPreKey: async () => undefined,
  }

  it('validates outgoing prekey bundle fields', async () => {
    const builder = new SessionBuilder(storage, new ProtocolAddress('peer', 1))

    await expect(builder.initOutgoing(undefined as never)).rejects.toThrow('device must be a PreKeyBundle')
    await expect(builder.initOutgoing({
      identityKey: new Uint8Array(),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32), signature: new Uint8Array(64) },
    })).rejects.toThrow('Invalid device.identityKey')

    await expect(builder.initOutgoing({
      identityKey: new Uint8Array(32),
      registrationId: 1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(), signature: new Uint8Array(64) },
    })).rejects.toThrow('Invalid device.signedPreKey.publicKey')

    await expect(builder.initOutgoing({
      identityKey: new Uint8Array(32),
      registrationId: -1,
      signedPreKey: { keyId: 1, publicKey: new Uint8Array(32), signature: new Uint8Array(64) },
    })).rejects.toThrow('Invalid device.registrationId')
  })

  it('throws prekey errors on incoming when missing signed prekey and invalid prekey id', async () => {
    const record = new SessionRecord()
    const builder = new SessionBuilder(storage, new ProtocolAddress('peer', 1))

    await expect(builder.initIncoming(record, {
      identityKey: new Uint8Array(32),
      registrationId: 1,
      baseKey: new Uint8Array(32),
      signedPreKeyId: 2,
      preKeyId: 3,
      message: new Uint8Array([1]),
    })).rejects.toThrow('Invalid PreKey ID')

    await expect(builder.initIncoming(record, {
      identityKey: new Uint8Array(32),
      registrationId: 1,
      baseKey: new Uint8Array(32),
      signedPreKeyId: 2,
      message: new Uint8Array([1]),
    })).rejects.toThrow('Missing SignedPreKey')
  })
})

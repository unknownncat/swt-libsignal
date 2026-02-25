import { describe, expect, it } from 'vitest'
import { initCrypto } from '../../src/curve'
import { ProtocolAddress } from '../../src/protocol_address'
import {
  GroupCipher,
  GroupSessionBuilder,
  SenderKeyDistributionMessage,
  SenderKeyName,
  SenderKeyRecord,
  type SenderAddress,
} from '../../src/signal/group'

class MemorySenderKeyStore {
  private readonly records = new Map<string, Uint8Array>()

  async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord> {
    const data = this.records.get(senderKeyName.toString())
    return data ? SenderKeyRecord.deserialize(data) : new SenderKeyRecord()
  }

  async storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void> {
    this.records.set(senderKeyName.toString(), record.serializeToBytes())
  }
}

function toSenderAddress(address: ProtocolAddress): SenderAddress {
  return {
    id: address.id,
    deviceId: address.deviceId,
    toString: () => address.toString(),
  }
}

describe('signal group sender keys', () => {
  it('creates distribution message and roundtrips group ciphertext', async () => {
    await initCrypto()
    const aliceStore = new MemorySenderKeyStore()
    const bobStore = new MemorySenderKeyStore()

    const aliceAddr = new ProtocolAddress('alice', 1)
    const senderName = new SenderKeyName('group-1', toSenderAddress(aliceAddr))
    const aliceBuilder = new GroupSessionBuilder(aliceStore)
    const bobBuilder = new GroupSessionBuilder(bobStore)

    const distribution = await aliceBuilder.create(senderName)
    await bobBuilder.process(
      senderName,
      new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, distribution.serialize())
    )

    const aliceCipher = new GroupCipher(aliceStore, senderName)
    const bobCipher = new GroupCipher(bobStore, senderName)

    const plaintext = new TextEncoder().encode('group-secret-message')
    const ciphertext = await aliceCipher.encrypt(plaintext)
    const decrypted = await bobCipher.decrypt(ciphertext)
    expect(decrypted).toEqual(plaintext)

    await expect(bobCipher.decrypt(ciphertext)).rejects.toThrow('Received message with old counter')
  })

  it('rejects tampered sender key signature', async () => {
    await initCrypto()
    const aliceStore = new MemorySenderKeyStore()
    const bobStore = new MemorySenderKeyStore()
    const senderName = new SenderKeyName(
      'group-2',
      { id: 'alice', deviceId: 1, toString: () => 'alice.1' }
    )

    const aliceBuilder = new GroupSessionBuilder(aliceStore)
    const bobBuilder = new GroupSessionBuilder(bobStore)
    const distribution = await aliceBuilder.create(senderName)
    await bobBuilder.process(senderName, new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, distribution.serialize()))

    const aliceCipher = new GroupCipher(aliceStore, senderName)
    const bobCipher = new GroupCipher(bobStore, senderName)
    const ciphertext = await aliceCipher.encrypt(new TextEncoder().encode('integrity'))

    const tampered = ciphertext.slice()
    tampered[tampered.length - 1] ^= 0x01
    await expect(bobCipher.decrypt(tampered)).rejects.toThrow('Invalid signature')
  })
})

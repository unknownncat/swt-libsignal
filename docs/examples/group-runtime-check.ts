import { initCrypto } from '../../src/curve'
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
    const encoded = this.records.get(senderKeyName.toString())
    return encoded ? SenderKeyRecord.deserialize(encoded) : new SenderKeyRecord()
  }

  async storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void> {
    this.records.set(senderKeyName.toString(), record.serializeToBytes())
  }
}

function senderAddress(id: string, deviceId: number): SenderAddress {
  const text = `${id}.${deviceId}`
  return {
    id,
    deviceId,
    toString: () => text
  }
}

export interface GroupRuntimeCheckResult {
  readonly distributionBytes: number
  readonly ciphertextBytes: number
  readonly plaintextMatch: boolean
}

export async function runGroupRuntimeCheck(): Promise<GroupRuntimeCheckResult> {
  await initCrypto()
  const aliceStore = new MemorySenderKeyStore()
  const bobStore = new MemorySenderKeyStore()
  const senderName = new SenderKeyName('docs-group', senderAddress('alice', 1))

  const aliceBuilder = new GroupSessionBuilder(aliceStore)
  const bobBuilder = new GroupSessionBuilder(bobStore)
  const distribution = await aliceBuilder.create(senderName)
  await bobBuilder.process(
    senderName,
    new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, distribution.serialize())
  )

  const aliceCipher = new GroupCipher(aliceStore, senderName)
  const bobCipher = new GroupCipher(bobStore, senderName)

  const plaintext = new TextEncoder().encode('docs-group-message')
  const ciphertext = await aliceCipher.encrypt(plaintext)
  const opened = await bobCipher.decrypt(ciphertext)

  return {
    distributionBytes: distribution.serialize().length,
    ciphertextBytes: ciphertext.length,
    plaintextMatch: Buffer.from(plaintext).equals(Buffer.from(opened)),
  }
}

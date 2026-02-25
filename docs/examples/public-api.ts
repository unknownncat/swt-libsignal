import {
  ProtocolAddress,
  SessionRecord,
  SessionEntry,
  BaseKeyType,
  crypto,
  createSignalSync,
  enqueue,
  type AddressId,
} from '../../src/public/index'

function createExampleSession(id: number): SessionEntry {
  const entry = new SessionEntry()
  const byte = id & 0xff

  entry.registrationId = 1000 + id
  entry.currentRatchet = {
    ephemeralKeyPair: {
      pubKey: new Uint8Array(32).fill(byte),
      privKey: new Uint8Array(32).fill((byte + 1) & 0xff),
    },
    lastRemoteEphemeralKey: new Uint8Array(32).fill((byte + 2) & 0xff),
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill((byte + 3) & 0xff),
  }

  entry.indexInfo = {
    baseKey: new Uint8Array(32).fill((byte + 4) & 0xff),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used: id,
    created: id,
    remoteIdentityKey: new Uint8Array(32).fill((byte + 5) & 0xff),
  }

  return entry
}

async function run(): Promise<void> {
  const addr = new ProtocolAddress('alice' as AddressId, 1)
  const record = new SessionRecord()
  record.setSession(createExampleSession(1))

  const queueResults: number[] = []
  await Promise.all([
    enqueue('example-bucket', async () => {
      queueResults.push(1)
      return 1
    }),
    enqueue('example-bucket', async () => {
      queueResults.push(2)
      return 2
    }),
  ])

  const syncApi = createSignalSync()
  const key = new Uint8Array(32).fill(7)
  const iv = new Uint8Array(12).fill(9)
  const message = new TextEncoder().encode('hello swt-libsignal')
  const encrypted = crypto.encrypt(key, message, { iv })
  const decrypted = syncApi.decrypt(key, encrypted)

  console.log('address:', addr.toString())
  console.log('sessions:', record.getSessions().length)
  console.log('queue order:', queueResults.join(','))
  console.log('decrypted:', new TextDecoder().decode(decrypted))
}

void run()

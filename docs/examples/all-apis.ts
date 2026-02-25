import {
  crypto,
  cryptoAsync,
  createSignalSync,
  createSignalAsync,
  initCrypto,
  signalCrypto,
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
  FingerprintGenerator,
  ProtocolAddress,
  WhisperMessageCodec,
  PreKeyWhisperMessageCodec,
  SessionRecord,
  SessionEntry,
  BaseKeyType,
  ChainType,
  enqueue,
} from '../../src/index'
import { flushQueue } from '../../src/job_queue'
import {
  InMemoryStorage,
  createSessionStorage,
  AtomicJsonFileAsyncStorageAdapter,
  createStorageManager,
} from '../../src/session/storage'

async function run(): Promise<void> {
  const msg = new TextEncoder().encode('docs example')

  // ── Crypto Sync / Async / Dual ─────────────────────────────────────
  const key = new Uint8Array(32).fill(1)
  const sealed = crypto.encrypt(key, msg)
  const opened = crypto.decrypt(key, sealed)

  const sealedAsync = await cryptoAsync.encrypt(key, msg)
  const openedAsync = await cryptoAsync.decrypt(key, sealedAsync)

  const syncApi = createSignalSync()
  const asyncApi = await createSignalAsync({ workers: 4 })
  const sealedDual = syncApi.encrypt(key, msg)
  const openedDual = await asyncApi.decrypt(key, sealedDual)
  await asyncApi.close()

  // ── Curve + Helpers ───────────────────────────────────────────────
  await initCrypto()
  const id = await signalCrypto.generateIdentityKeyPair()
  const dhA = await signalCrypto.generateDHKeyPair()
  const dhB = await signalCrypto.generateDHKeyPair()
  const sharedA = signalCrypto.calculateAgreement(dhB.publicKey, dhA.privateKey)
  const sharedB = signalCrypto.calculateAgreement(dhA.publicKey, dhB.privateKey)
  const sig = signalCrypto.sign(id.privateKey, msg)
  const sigOk = signalCrypto.verify(id.publicKey, msg, sig)

  const registrationId = generateRegistrationId()
  const signed = await generateSignedPreKey(id, 9)
  const pre = await generatePreKey(10)

  // ── Fingerprint + Address ─────────────────────────────────────────
  const fp = new FingerprintGenerator(10).createFor('alice', id.publicKey, 'bob', id.publicKey)
  const address = new ProtocolAddress('alice', 1)
  const parsed = ProtocolAddress.from(address.toString())

  // ── Protobuf codecs ───────────────────────────────────────────────
  const whisperBytes = WhisperMessageCodec.encode({
    ephemeralKey: dhA.publicKey,
    counter: 1,
    previousCounter: 0,
    ciphertext: msg,
  })
  const whisperDecoded = WhisperMessageCodec.decode(whisperBytes)

  const preKeyBytes = PreKeyWhisperMessageCodec.encode({
    registrationId,
    preKeyId: pre.keyId,
    signedPreKeyId: signed.keyId,
    baseKey: pre.keyPair.publicKey,
    identityKey: id.publicKey,
    message: whisperBytes,
  })
  const preKeyDecoded = PreKeyWhisperMessageCodec.decode(preKeyBytes)

  // ── SessionRecord ─────────────────────────────────────────────────
  const entry = new SessionEntry()
  entry.registrationId = registrationId
  entry.currentRatchet = {
    ephemeralKeyPair: { pubKey: dhA.publicKey, privKey: dhA.privateKey },
    lastRemoteEphemeralKey: dhB.publicKey,
    previousCounter: 0,
    rootKey: sharedA,
  }
  entry.indexInfo = {
    baseKey: pre.keyPair.publicKey,
    baseKeyType: BaseKeyType.OURS,
    closed: -1,
    used: 1,
    created: 1,
    remoteIdentityKey: id.publicKey,
  }
  entry.addChain(dhA.publicKey, {
    chainType: ChainType.SENDING,
    chainKey: { counter: 0, key: new Uint8Array(32).fill(7) },
    messageKeys: new Map(),
  })

  const record = new SessionRecord()
  record.setSession(entry)
  const restored = SessionRecord.deserialize(record.serialize())

  // ── Storage (InMemory + Atomic JSON File) ─────────────────────────
  const adapter = new InMemoryStorage<unknown>()
  const sessionStorage = createSessionStorage(adapter)
  await sessionStorage.storeBootstrap({ pubKey: dhA.publicKey, privKey: dhA.privateKey }, registrationId)
  await sessionStorage.storeSession(address.toString(), restored)
  const loaded = await sessionStorage.loadSession(address.toString())

  const manager = createStorageManager(new InMemoryStorage<Uint8Array>())
  await manager.set('raw', new Uint8Array([1, 2, 3]))

  // Demo persistente no disco
  const fileAdapter = new AtomicJsonFileAsyncStorageAdapter('./tmp/docs-storage.json', { flushEveryWrites: 1 })
  await fileAdapter.set('demo', new Uint8Array([5, 6, 7, 8, 9]))
  const persisted = await fileAdapter.get('demo')

  await fileAdapter.zeroize('demo')   // só na memória

  console.log('✅ Arquivo JSON persistido com sucesso:')

  // @ts-ignore
  console.log(await import('node:fs/promises').then(fs => fs.readFile('./tmp/docs-storage.json', 'utf8')))

  // Não limpamos o arquivo para o exemplo ficar visível
  await fileAdapter.close()

  // ── Job Queue ─────────────────────────────────────────────────────
  const order: number[] = []
  await Promise.all([
    enqueue('docs', async () => { order.push(1); return 1 }),
    enqueue('docs', async () => { order.push(2); return 2 }),
  ])
  await flushQueue('docs')

  // Resultado final
  console.log({
    opened: opened.length,
    openedAsync: openedAsync.length,
    openedDual: openedDual.length,
    // @ts-ignore
    sharedEq: Buffer.from(sharedA).equals(Buffer.from(sharedB)),
    sigOk,
    fpLength: fp.length,
    address: parsed.toString(),
    whisperCounter: whisperDecoded.counter,
    preKeyReg: preKeyDecoded.registrationId,
    sessions: loaded?.getSessions().length ?? 0,
    order,
    persistedDemo: persisted,
  })
}

void run()
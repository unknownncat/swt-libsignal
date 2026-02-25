import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { BaseKeyType, ChainType } from '../../src/ratchet-types'
import {
  AtomicJsonFileAsyncStorageAdapter,
  InMemoryStorage,
  StorageManager,
  createInMemoryStorage,
  createSessionStorage,
  createStorageManager,
} from '../../src/session/storage'
import { Deque } from '../../src/internal/queue/deque'
import { enqueue } from '../../src/job_queue'
import { deleteMany, getMany, setMany } from '../../src/session/storage/runtime'
import { runMigrations } from '../../src/session/storage/migrations'
import { SessionEntry, SessionRecord } from '../../src/session/record'
import { LIDMappingStore } from '../../src/signal/lid-mapping'
import {
  GroupCipher,
  GroupSessionBuilder,
  SenderKeyDistributionMessage,
  SenderKeyMessage,
  SenderKeyName,
  SenderKeyRecord,
  SenderKeyState,
  SenderMessageKey,
} from '../../src/signal/group'
import { generateSenderSigningKey } from '../../src/signal/group/keyhelper'
import { SenderKeyDistributionMessageCodec, SenderKeyMessageCodec } from '../../src/signal/group/proto'
import { PreKeyWhisperMessageCodec, WhisperMessageCodec } from '../../src/proto/generated/whisper-text-protocol'

afterEach(() => {
  vi.restoreAllMocks()
})

function senderAddress(id = 'alice', deviceId = 1) {
  return {
    id,
    deviceId,
    toString: () => `${id}.${deviceId}`,
  }
}

function makeSessionEntry(idByte: number, closed = -1, used = 1): SessionEntry {
  const entry = new SessionEntry()
  entry.registrationId = idByte
  entry.currentRatchet = {
    ephemeralKeyPair: { pubKey: new Uint8Array(32).fill(idByte), privKey: new Uint8Array(32).fill(idByte + 1) },
    lastRemoteEphemeralKey: new Uint8Array(32).fill(idByte + 2),
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill(idByte + 3),
  }
  entry.indexInfo = {
    baseKey: new Uint8Array(32).fill(idByte + 4),
    baseKeyType: BaseKeyType.THEIRS,
    closed,
    used,
    created: used,
    remoteIdentityKey: new Uint8Array(32).fill(idByte + 5),
  }
  return entry
}

describe('coverage - storage + group + proto + lid mapping', () => {
  it('covers session storage identity policy branches and decode shape guard', async () => {
    const adapter = new InMemoryStorage<unknown>()

    const firstUseGuard = createSessionStorage(adapter, {
      onFirstUseIdentity: async () => false,
    })
    await expect(firstUseGuard.isTrustedIdentity('alice', new Uint8Array([1]))).resolves.toBe(false)

    const tofuOff = createSessionStorage(adapter, { trustOnFirstUse: false })
    await expect(tofuOff.isTrustedIdentity('bob', new Uint8Array([1]))).resolves.toBe(false)

    adapter.set('identity:carol', new Uint8Array([1]))
    const rejectOnMismatch = createSessionStorage(adapter, {
      onIdentityMismatch: async () => 'reject',
    })
    await expect(rejectOnMismatch.isTrustedIdentity('carol', new Uint8Array([2]))).resolves.toBe(false)

    const replaceOnMismatch = createSessionStorage(adapter, {
      onIdentityMismatch: async () => 'replace',
    })
    await expect(replaceOnMismatch.isTrustedIdentity('carol', new Uint8Array([2]))).resolves.toBe(true)

    adapter.set('identity:dave', Buffer.from([7]).toString('base64'))
    await expect(replaceOnMismatch.isTrustedIdentity('dave', new Uint8Array([7]))).resolves.toBe(true)

    adapter.set('our_identity', { pubKey: 1 as never, privKey: 'x' as never })
    await expect(replaceOnMismatch.getOurIdentity()).rejects.toThrow('Invalid identity storage shape')
  })

  it('covers loadPreKeyPair branches, prefetch branch and atomic prekey/session variants', async () => {
    const prefetch = vi.fn(async () => undefined)
    const zeroize = vi.fn()
    const adapter = new InMemoryStorage<unknown>() as InMemoryStorage<unknown> & {
      prefetch: (keys: readonly string[]) => Promise<void>
      zeroize: (key: string) => void
      transaction: <T>(run: (tx: unknown) => Promise<T>) => Promise<T>
    }
    adapter.prefetch = prefetch
    adapter.zeroize = zeroize
    adapter.transaction = async (run) => run(adapter)

    adapter.set('signedprekey:11', { pubKey: new Uint8Array([1]), privKey: new Uint8Array([2]) })
    adapter.set('prekey:7', { pubKey: new Uint8Array([3]), privKey: new Uint8Array([4]) })
    adapter.set('our_identity', {
      pubKey: Buffer.from([9]).toString('base64'),
      privKey: Buffer.from([8]).toString('base64'),
    })

    const store = createSessionStorage(adapter)

    await expect(store.getOurIdentity()).resolves.toEqual({ pubKey: new Uint8Array([9]), privKey: new Uint8Array([8]) })
    await expect(store.loadPreKey(7)).resolves.toEqual({ pubKey: new Uint8Array([3]), privKey: new Uint8Array([4]) })
    await expect(store.loadSignedPreKey(11)).resolves.toEqual({ pubKey: new Uint8Array([1]), privKey: new Uint8Array([2]) })
    await expect(store.loadPreKey(999)).resolves.toBeUndefined()
    await expect(store.loadSignedPreKey(999)).resolves.toBeUndefined()

    const pairNoPre = await store.loadPreKeyPair(undefined, 11)
    expect(pairNoPre[0]).toBeUndefined()
    expect(pairNoPre[1]?.pubKey).toEqual(new Uint8Array([1]))

    const pairWithPre = await store.loadPreKeyPair(7, 11)
    expect(pairWithPre[0]?.pubKey).toEqual(new Uint8Array([3]))
    expect(pairWithPre[1]?.pubKey).toEqual(new Uint8Array([1]))

    const pairMissingSigned = await store.loadPreKeyPair(undefined, 999)
    expect(pairMissingSigned[1]).toBeUndefined()

    const pairMissingBoth = await store.loadPreKeyPair(999, 999)
    expect(pairMissingBoth[0]).toBeUndefined()
    expect(pairMissingBoth[1]).toBeUndefined()

    await store.primeSession('eve')
    expect(prefetch).toHaveBeenCalledOnce()

    const record = new SessionRecord()
    await store.storeSessionAndRemovePreKey('eve.1', record, 7)
    expect(zeroize).toHaveBeenCalledWith('prekey:7')

    const fallbackAdapter = new InMemoryStorage<unknown>() as InMemoryStorage<unknown> & {
      zeroize: (key: string) => void
    }
    const fallbackZeroize = vi.fn()
    fallbackAdapter.zeroize = fallbackZeroize
    const fallbackStore = createSessionStorage(fallbackAdapter)
    await fallbackStore.storeSessionAndRemovePreKey('fallback.1', record, 9)
    expect(fallbackZeroize).toHaveBeenCalledWith('prekey:9')

    const guardedStore = createSessionStorage(new InMemoryStorage<unknown>(), {
      requireAtomicSessionAndPreKey: true,
    })
    await expect(guardedStore.storeSessionAndRemovePreKey('x.1', new SessionRecord(), 1)).rejects.toThrow('Atomic session+prekey operation requires adapter.transaction() support')

    await fallbackStore.removePreKey(9)

    adapter.set('identity:length-mismatch', new Uint8Array([1]))
    await expect(store.isTrustedIdentity('length-mismatch', new Uint8Array([1, 2]))).resolves.toBe(false)
  })

  it('covers runtime async fallbacks, explicit batch branches and migrations', async () => {
    const backing = new Map<string, number>()
    const asyncAdapter = {
      get: async (key: string) => backing.get(key),
      set: async (key: string, value: number) => { backing.set(key, value) },
      delete: async (key: string) => { backing.delete(key) },
    }

    await setMany(asyncAdapter, [{ key: 'a', value: 1 }, { key: 'b', value: 2 }])
    await expect(getMany(asyncAdapter, ['a', 'x'])).resolves.toEqual([1, undefined])
    await deleteMany(asyncAdapter, [{ key: 'a' }])
    expect(backing.has('a')).toBe(false)

    const adapterWithBatch = {
      ...asyncAdapter,
      deleteMany: vi.fn(async () => undefined),
      setMany: vi.fn(async () => undefined),
      getMany: vi.fn(async () => [9]),
    }

    await deleteMany(adapterWithBatch, [{ key: 'k' }])
    await setMany(adapterWithBatch, [{ key: 'k', value: 1 }])
    await expect(getMany(adapterWithBatch, ['k'])).resolves.toEqual([9])
    expect(adapterWithBatch.deleteMany).toHaveBeenCalledOnce()
    expect(adapterWithBatch.setMany).toHaveBeenCalledOnce()
    expect(adapterWithBatch.getMany).toHaveBeenCalledOnce()

    const migrator = { ...asyncAdapter, migrate: vi.fn(async () => undefined) }
    await runMigrations(asyncAdapter, 1, 2)
    await runMigrations(migrator, 1, 2)
    expect(migrator.migrate).toHaveBeenCalledWith(1, 2)
  })

  it('covers in-memory shared mode + storage manager wrappers', async () => {
    const isolated = new InMemoryStorage<Uint8Array>({ copy: new Uint8Array([1]) })
    const isolatedOut = isolated.get('copy')!
    isolatedOut[0] = 9
    expect(isolated.get('copy')?.[0]).toBe(1)
    isolated.set('copy', isolatedOut)
    isolatedOut[0] = 7
    expect(isolated.get('copy')?.[0]).toBe(9)

    const shared = new InMemoryStorage<Uint8Array>({ key: new Uint8Array([1]) }, { mutability: 'shared' })
    const out = shared.get('key')
    expect(out).toBeDefined()
    out![0] = 9
    expect(shared.get('key')?.[0]).toBe(9)
    const sharedWritten = new Uint8Array([4])
    shared.set('sharedWrite', sharedWritten)
    sharedWritten[0] = 7
    expect(shared.get('sharedWrite')?.[0]).toBe(7)
    shared.clear()

    const mixed = new InMemoryStorage<unknown>({ any: 1 as never })
    mixed.clear({ secure: true })

    const factory = createStorageManager(new InMemoryStorage<number>())
    await factory.set('n', 7)
    await expect(Promise.resolve(factory.get('n'))).resolves.toBe(7)
    await factory.setMany([{ key: 'x', value: 1 }])
    await expect(Promise.resolve(factory.getMany(['x']))).resolves.toEqual([1])
    await factory.deleteMany([{ key: 'x' }])
    await factory.delete('n')
    await factory.close()

    const manager = new StorageManager(new InMemoryStorage<number>())
    await manager.set('a', 1)
    await manager.delete('a')

    const viaFactory = createStorageManager(new InMemoryStorage<number>())
    expect(viaFactory).toBeInstanceOf(StorageManager)

    const fromFactory = createInMemoryStorage({ z: new Uint8Array([5]) }, { mutability: 'shared' })
    expect(fromFactory.get('z')?.[0]).toBe(5)
  })

  it('covers deque and queue edge branches', async () => {
    const deque = new Deque<number>()
    for (let i = 0; i < 10; i++) deque.push(i)
    deque.spliceFront(1)
    deque.push(1)
    deque.spliceFront(0)
    expect(deque.at(-1)).toBeUndefined()
    deque.clear()
    expect(deque.length).toBe(0)

    expect(() => enqueue('timeout-edge', async () => 1, { timeoutMs: 0 })).toThrow('timeoutMs must be a positive integer')

    const originalShift = Deque.prototype.shift
    const shiftSpy = vi.spyOn(Deque.prototype, 'shift')
    shiftSpy.mockImplementationOnce(function (this: Deque<unknown>) {
      return undefined
    })
    shiftSpy.mockImplementation(function (this: Deque<unknown>) {
      return originalShift.call(this)
    })

    await expect(enqueue('queue-continue-edge', async () => 1)).resolves.toBe(1)
    shiftSpy.mockRestore()
  })

  it('covers atomic file adapter init catch, lazy flush, fsync and secure clear', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'swt-storage-'))
    const lazyPath = join(dir, 'lazy.json')
    const fsyncPath = join(dir, 'fsync.json')
    const preloadedPath = join(dir, 'preloaded.json')

    const lazy = new AtomicJsonFileAsyncStorageAdapter(lazyPath, { flushEveryWrites: 10 })
    await expect(lazy.get('missing')).resolves.toBeUndefined()
    await lazy.set('k', new Uint8Array([1, 2, 3]))
    await expect(stat(lazyPath)).rejects.toThrow()
    await lazy.setMany([{ key: 'x', value: new Uint8Array([9]) }])
    await lazy.deleteMany([{ key: 'x' }])
    await lazy.delete('k')
    await lazy.close()

    const fsyncAdapter = new AtomicJsonFileAsyncStorageAdapter(fsyncPath, {
      flushEveryWrites: 1,
      fsyncOnFlush: true,
    })

    await fsyncAdapter.set('a', new Uint8Array([7, 7]))
    await fsyncAdapter.clear()
    await fsyncAdapter.zeroize('a')
    ;(fsyncAdapter as unknown as { map: Map<string, unknown> }).map.set('non-u8', 'x')
    await fsyncAdapter.zeroize('non-u8')
    await fsyncAdapter.clear({ secure: true })
    await fsyncAdapter.close()

    const persisted = await readFile(fsyncPath, 'utf8')
    expect(persisted).toContain('{')

    await rm(preloadedPath, { force: true })
    await new AtomicJsonFileAsyncStorageAdapter(preloadedPath, { flushEveryWrites: 1 })
      .set('warm', new Uint8Array([4]))
    const loaded = new AtomicJsonFileAsyncStorageAdapter(preloadedPath)
    await expect(loaded.get('warm')).resolves.toEqual(new Uint8Array([4]))
    await loaded.close()

    await rm(dir, { recursive: true, force: true })
  })

  it('covers sender key names/state/record/message/distribution edges', async () => {
    const longName = new SenderKeyName('g'.repeat(200), senderAddress())
    expect(longName.getGroupId().length).toBe(200)
    expect(longName.getSender().id).toBe('alice')
    expect(longName.equals(null)).toBe(false)
    expect(longName.equals(new SenderKeyName('g'.repeat(200), senderAddress()))).toBe(true)
    expect(typeof longName.hashCode()).toBe('number')

    const structured = new SenderKeyState(
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      {
        senderKeyId: 1,
        senderChainKey: { iteration: 0, seed: '' },
        senderSigningKey: { public: '' },
        senderMessageKeys: null as never,
      }
    )
    expect(structured.getStructure().senderMessageKeys).toEqual([])

    const defaults = new SenderKeyState()
    expect(defaults.getKeyId()).toBe(0)
    expect(defaults.getSenderChainKey().getIteration()).toBe(0)
    expect(defaults.getSigningKeyPublic()).toEqual(new Uint8Array(0))

    const rolling = new SenderKeyState(1, 0, new Uint8Array([1]), undefined, new Uint8Array([2]))
    for (let i = 0; i < 2001; i++) {
      rolling.addSenderMessageKey({
        getIteration: () => i,
        getSeed: () => new Uint8Array([i & 0xff || 1]),
      } as unknown as SenderMessageKey)
    }
    expect(rolling.hasSenderMessageKey(2000)).toBe(true)
    expect(rolling.removeSenderMessageKey(2000)?.getIteration()).toBe(2000)
    expect(rolling.removeSenderMessageKey(999999)).toBeUndefined()

    const record = new SenderKeyRecord()
    for (let i = 0; i < 6; i++) {
      record.addSenderKeyState(i, 0, new Uint8Array(32).fill(i + 1), new Uint8Array(33).fill(i + 2))
    }
    expect(record.getSenderKeyState(0)).toBeUndefined()
    const packed = record.serializeToBytes()
    expect(SenderKeyRecord.deserialize(packed)).toBeInstanceOf(SenderKeyRecord)

    expect(() => new SenderKeyMessage()).toThrow('Invalid SenderKeyMessage constructor arguments')
    expect(() => new SenderKeyMessage(undefined, undefined, undefined, undefined, new Uint8Array(10))).toThrow('Invalid SenderKeyMessage payload')
    const malformedSenderMessage = new Uint8Array(67)
    malformedSenderMessage[0] = 0x33
    malformedSenderMessage[1] = 0x08
    malformedSenderMessage[2] = 0x01
    expect(() => new SenderKeyMessage(undefined, undefined, undefined, undefined, malformedSenderMessage)).toThrow('Invalid SenderKeyMessage payload')

    const signing = await generateSenderSigningKey()
    const senderMessage = new SenderKeyMessage(7, 1, new Uint8Array(16).fill(9), signing.private)
    expect(() => senderMessage.verifySignature(new Uint8Array(31))).toThrow('Invalid sender signing public key')
    expect(() => senderMessage.verifySignature(new Uint8Array(32).fill(1))).toThrow('Invalid signature')
    expect(senderMessage.getType()).toBeGreaterThan(0)

    const mk = new SenderMessageKey(1, new Uint8Array([1]))
    expect(mk.getSeed()).toEqual(new Uint8Array([1]))

    expect(() => new SenderKeyDistributionMessage()).toThrow('Invalid SenderKeyDistributionMessage constructor arguments')
    expect(() => new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, new Uint8Array([1]))).toThrow('Invalid SenderKeyDistributionMessage payload')
    const malformedDist = new Uint8Array([0x33, 0x00, 0x00])
    expect(() => new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, malformedDist)).toThrow('Invalid SenderKeyDistributionMessage payload')

    const dist = new SenderKeyDistributionMessage(5, 0, new Uint8Array([1]), signing.public)
    expect(dist.getId()).toBe(5)
    expect(dist.getType()).toBeGreaterThan(0)
  })

  it('covers group cipher and group session builder hard error paths', async () => {
    const name = new SenderKeyName('group-a', senderAddress())

    const emptyStore = {
      loadSenderKey: async () => new SenderKeyRecord(),
      storeSenderKey: async () => undefined,
    }

    const emptyCipher = new GroupCipher(emptyStore, name)
    await expect(emptyCipher.encrypt(new Uint8Array([1]))).rejects.toThrow('No sender key state to encrypt message')

    const noPrivateRecord = new SenderKeyRecord()
    noPrivateRecord.addSenderKeyState(1, 0, new Uint8Array(32).fill(1), new Uint8Array(33).fill(2))
    const noPrivateStore = {
      loadSenderKey: async () => noPrivateRecord,
      storeSenderKey: async () => undefined,
    }

    const noPrivateCipher = new GroupCipher(noPrivateStore, name)
    await expect(noPrivateCipher.encrypt(new Uint8Array([1]))).rejects.toThrow('Missing sender signing private key')

    const signing = await generateSenderSigningKey()
    const senderMsg = new SenderKeyMessage(99, 0, new Uint8Array(16).fill(9), signing.private)
    await expect(emptyCipher.decrypt(senderMsg.serialize())).rejects.toThrow('No sender key state to decrypt message')

    const internals = noPrivateCipher as unknown as {
      getSenderKey: (state: unknown, iteration: number) => unknown
      getPlainText: (iv: Uint8Array, key: Uint8Array, ciphertext: Uint8Array) => Uint8Array
      getCipherText: (iv: Uint8Array, key: Uint8Array, plaintext: Uint8Array) => Uint8Array
    }

    expect(() => internals.getSenderKey({
      getSenderChainKey: () => ({ getIteration: () => 10 }),
      hasSenderMessageKey: () => true,
      removeSenderMessageKey: () => undefined,
    }, 1)).toThrow('No sender message key for iteration')

    const reusableKey = {
      getIteration: () => 1,
      getIv: () => new Uint8Array(16),
      getCipherKey: () => new Uint8Array(32),
      getSeed: () => new Uint8Array([1]),
    }
    expect(internals.getSenderKey({
      getSenderChainKey: () => ({ getIteration: () => 10 }),
      hasSenderMessageKey: () => true,
      removeSenderMessageKey: () => reusableKey,
    }, 1)).toBe(reusableKey)

    expect(() => internals.getSenderKey({
      getSenderChainKey: () => ({ getIteration: () => 0 }),
      hasSenderMessageKey: () => false,
    }, 3001)).toThrow('Over 2000 messages into the future')

    const keyFlowState = {
      getSenderChainKey: () => ({
        getIteration: () => 0,
        getSenderMessageKey: () => reusableKey,
        getNext: () => ({
          getIteration: () => 1,
          getSenderMessageKey: () => reusableKey,
          getNext: () => ({ getIteration: () => 2 }),
        }),
      }),
      addSenderMessageKey: vi.fn(),
      setSenderChainKey: vi.fn(),
    }
    internals.getSenderKey(keyFlowState, 1)
    expect(keyFlowState.addSenderMessageKey).toHaveBeenCalled()
    expect(keyFlowState.setSenderChainKey).toHaveBeenCalled()

    expect(() => internals.getPlainText(new Uint8Array(1), new Uint8Array(1), new Uint8Array([1]))).toThrow('Invalid group message ciphertext')
    expect(() => internals.getCipherText(new Uint8Array(1), new Uint8Array(1), new Uint8Array([1]))).toThrow('Invalid group message plaintext')

    const bufKey = Buffer.alloc(32, 1) as unknown as Uint8Array
    const bufIv = Buffer.alloc(16, 2) as unknown as Uint8Array
    const bufPayload = Buffer.from('hello-group') as unknown as Uint8Array
    const bufEncrypted = internals.getCipherText(bufIv, bufKey, bufPayload)
    const bufOpened = internals.getPlainText(bufIv, bufKey, bufEncrypted)
    expect(Buffer.from(bufOpened).toString('utf8')).toBe('hello-group')

    const rollingSigning = await generateSenderSigningKey()
    const rollingRecord = new SenderKeyRecord()
    rollingRecord.setSenderKeyState(42, 1, new Uint8Array(32).fill(9), rollingSigning)
    const rollingStore = {
      loadSenderKey: async () => rollingRecord,
      storeSenderKey: async () => undefined,
    }
    const rollingCipher = new GroupCipher(rollingStore, name)
    await expect(rollingCipher.encrypt(new Uint8Array([1, 2, 3]))).resolves.toBeInstanceOf(Uint8Array)

    const brokenBuilder = new GroupSessionBuilder({
      loadSenderKey: async () => ({
        isEmpty: () => false,
        getSenderKeyState: () => undefined,
      } as never),
      storeSenderKey: async () => undefined,
    })

    await expect(brokenBuilder.create(name)).rejects.toThrow('No sender key state available')
  })

  it('covers group and generated protobuf codec unknown/malformed wire branches', () => {
    expect(SenderKeyMessageCodec.encode({})).toEqual(new Uint8Array())
    expect(SenderKeyDistributionMessageCodec.encode({})).toEqual(new Uint8Array())
    expect(SenderKeyMessageCodec.decode(new Uint8Array([0x28, 0x01]))).toEqual({})
    expect(SenderKeyMessageCodec.decode(new Uint8Array([0x2a, 0x01, 0xff]))).toEqual({})
    expect(() => SenderKeyMessageCodec.decode(new Uint8Array([0x80]))).toThrow('Malformed varint')
    expect(() => SenderKeyMessageCodec.decode(new Uint8Array([0x0d]))).toThrow('Unsupported wire type: 5')

    expect(SenderKeyDistributionMessageCodec.decode(new Uint8Array([0x28, 0x01]))).toEqual({})
    expect(SenderKeyDistributionMessageCodec.decode(new Uint8Array([0x2a, 0x01, 0xff]))).toEqual({})

    const encodedWhisper = WhisperMessageCodec.encode({ counter: 1, previousCounter: 2 })
    expect(WhisperMessageCodec.decode(encodedWhisper).counter).toBe(1)
    expect(WhisperMessageCodec.decode(new Uint8Array([0x38, 0x01]))).toEqual({})
    expect(WhisperMessageCodec.decode(new Uint8Array([0x3a, 0x01, 0x00]))).toEqual({})
    expect(() => WhisperMessageCodec.decode(new Uint8Array([0x80]))).toThrow('Malformed varint')

    const encodedPre = PreKeyWhisperMessageCodec.encode({ registrationId: 1 })
    expect(PreKeyWhisperMessageCodec.decode(encodedPre).registrationId).toBe(1)
    expect(PreKeyWhisperMessageCodec.decode(new Uint8Array([0x38, 0x01]))).toEqual({})
    expect(() => PreKeyWhisperMessageCodec.decode(new Uint8Array([0x0d]))).toThrow('Unsupported wire type: 5')
  })

  it('covers lid mapping store cache/miss/key-store and no-key-store branches', async () => {
    const kv = new Map<string, string>()
    const keyStore = {
      get: vi.fn(async (keys: readonly string[]) => {
        const out: Record<string, string | undefined> = {}
        for (let i = 0; i < keys.length; i++) {
          out[keys[i]!] = kv.get(keys[i]!)
        }
        return out
      }),
      set: vi.fn(async (values: Record<string, string>) => {
        for (const [k, v] of Object.entries(values)) kv.set(k, v)
      }),
    }

    const withStore = new LIDMappingStore(keyStore)
    await withStore.storeLIDPNMappings([])
    await withStore.storeLIDPNMappings([
      { pn: '', lid: 'skip' },
      { pn: '111', lid: 'lid-111' },
    ])

    expect(keyStore.set).toHaveBeenCalledOnce()
    expect(await withStore.getLIDForPN('')).toBeNull()
    expect(await withStore.getPNForLID('')).toBeNull()

    kv.set('222', 'lid-222')
    kv.set('lid-222_reverse', '222')
    kv.set('lid-333_reverse', '333')

    const lids = await withStore.getLIDsForPNs(['111', '222', '111', ''])
    expect(lids.some((item) => item.pn === '111')).toBe(true)
    expect(lids.some((item) => item.pn === '222')).toBe(true)

    const pns = await withStore.getPNsForLIDs(['lid-111', 'lid-222', 'lid-111', ''])
    expect(pns.some((item) => item.lid === 'lid-111')).toBe(true)
    expect(pns.some((item) => item.lid === 'lid-222')).toBe(true)
    expect((await withStore.getPNsForLIDs(['lid-333'])).some((item) => item.pn === '333')).toBe(true)
    await expect(withStore.getPNsForLIDs(['lid-missing'])).resolves.toEqual([])

    const withoutStore = new LIDMappingStore()
    await withoutStore.storeLIDPNMappings([{ pn: 'x', lid: 'lid-x' }])
    await expect(withoutStore.getLIDsForPNs(['missing'])).resolves.toEqual([])
    await expect(withoutStore.getPNsForLIDs(['missing'])).resolves.toEqual([])
  })

  it('covers SessionRecord removeOldSessions removal path and SessionEntry edge helpers', () => {
    const record = new SessionRecord()

    for (let i = 0; i < 50; i++) {
      const entry = makeSessionEntry(i + 1, i < 45 ? i + 1 : -1, i + 1)
      record.setSession(entry)
    }

    record.removeOldSessions()
    expect(Object.keys(record.getSessionsMap()).length).toBeLessThanOrEqual(40)
    expect(record.sessions).toBeTypeOf('object')

    const deserializedWithoutSessions = SessionRecord.deserialize({ version: '1' } as never)
    expect(deserializedWithoutSessions.getSessions()).toEqual([])

    const empty = new SessionEntry()
    expect(empty.toString()).toContain('baseKey=')
    expect(empty.inspect()).toContain('SessionEntry')
    expect(() => empty.deleteChain(new Uint8Array([1]))).toThrow('Not Found')

    const chainKey = new Uint8Array([9])
    const entry = makeSessionEntry(9)
    entry.addChain(chainKey, {
      chainKey: { counter: 0, key: new Uint8Array([1]) },
      chainType: ChainType.SENDING,
      messageKeys: new Map(),
    })
    expect(() => entry.addChain(chainKey, {
      chainKey: { counter: 0, key: new Uint8Array([1]) },
      chainType: ChainType.SENDING,
      messageKeys: new Map(),
    })).toThrow('Overwrite attempt')
    expect(Array.from(entry.chains()).length).toBe(1)

    const clone = entry.clone()
    clone.pendingPreKey = { baseKey: new Uint8Array([3]), signedKeyId: 4, preKeyId: 5 }
    entry.replaceWith(clone)
    expect(entry.pendingPreKey?.signedKeyId).toBe(4)

    ;(entry as unknown as { _chains: Map<string, unknown> })._chains.set('stale', undefined)
    entry.serialize()

    const serialized = entry.serialize() as Record<string, unknown>
    ;(serialized._chains as Record<string, unknown>).stale = undefined
    SessionEntry.deserialize(serialized as never)

    const ours = makeSessionEntry(111)
    ours.indexInfo.baseKeyType = BaseKeyType.OURS
    record.setSession(ours)
    expect(() => record.getSession(ours.indexInfo.baseKey)).toThrow('Tried to lookup a session using our basekey')
    record.openSession(ours)
    record.closeSession(ours)
    record.closeSession(ours)

    const sameKeyA = makeSessionEntry(201, -1, 1)
    const sameKeyB = makeSessionEntry(202, -1, 2)
    sameKeyB.indexInfo.baseKey = sameKeyA.indexInfo.baseKey
    record.setSession(sameKeyA)
    record.setSession(sameKeyB)

    const undefinedUsedA = makeSessionEntry(210, -1, 1)
    const undefinedUsedB = makeSessionEntry(211, -1, 1)
    ;(undefinedUsedA.indexInfo as { used?: number }).used = undefined
    ;(undefinedUsedB.indexInfo as { used?: number }).used = undefined
    record.setSession(undefinedUsedA)
    record.setSession(undefinedUsedB)

    const accessorTarget = Object.keys(record.sessions).find((key) => record.sessions[key]?.indexInfo.closed !== -1)
    if (accessorTarget) {
      const original = record.sessions[accessorTarget]!
      let reads = 0
      Object.defineProperty(record.sessions, accessorTarget, {
        configurable: true,
        enumerable: true,
        get() {
          reads += 1
          return reads === 1 ? original : undefined
        },
      })
      record.removeOldSessions()
    }

    ;(record as unknown as { removeFromSortedSessions: (s: SessionEntry) => void })
      .removeFromSortedSessions(new SessionEntry())
  })
})

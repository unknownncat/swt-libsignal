import { afterEach, describe, expect, it, vi } from 'vitest'
import { makeLibSignalRepository } from '../../src/signal/libsignal'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import { SessionCipher } from '../../src/session/cipher/session-cipher'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage, SenderKeyRecord } from '../../src/signal/group'
import { SessionRecord } from '../../src/session/record'

afterEach(() => {
  vi.restoreAllMocks()
})

function makeStore(overrides: Record<string, unknown> = {}) {
  return {
    isTrustedIdentity: vi.fn(async () => true),
    loadSession: vi.fn(async () => undefined),
    storeSession: vi.fn(async () => undefined),
    getOurIdentity: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) })),
    loadPreKey: vi.fn(async () => undefined),
    loadSignedPreKey: vi.fn(async () => ({ pubKey: new Uint8Array(32).fill(3), privKey: new Uint8Array(32).fill(4) })),
    removePreKey: vi.fn(async () => undefined),
    getOurRegistrationId: vi.fn(async () => 7),
    loadSenderKey: vi.fn(async () => new SenderKeyRecord()),
    storeSenderKey: vi.fn(async () => undefined),
    storeBootstrap: vi.fn(async () => undefined),
    ...overrides,
  }
}

describe('coverage - libsignal repository branches', () => {
  it('covers jid mapping and pkmsg identity extraction guard paths', async () => {
    const decryptPre = vi.spyOn(SessionCipher.prototype, 'decryptPreKeyWhisperMessage').mockResolvedValue(new Uint8Array([9]))
    const decryptMsg = vi.spyOn(SessionCipher.prototype, 'decryptWhisperMessage').mockResolvedValue(new Uint8Array([8]))
    const encryptSpy = vi.spyOn(SessionCipher.prototype, 'encrypt')
      .mockResolvedValueOnce({ type: 3, body: new Uint8Array([1, 2]), registrationId: 1 })
      .mockResolvedValueOnce({ type: 1, body: new Uint8Array([3, 4]), registrationId: 1 })

    const store = makeStore({
      saveIdentity: vi.fn(async () => true),
    })
    const repo = makeLibSignalRepository(store)

    // defaultToProtocolAddress no-dot path
    expect(repo.jidToSignalProtocolAddress('alice')).toBe('alice.0')
    expect(repo.jidToSignalProtocolAddress('alice.1')).toBe('alice.1')

    // tryExtractIdentityFromPkmsg: ciphertext too short
    await expect(repo.decryptMessage({
      jid: 'bob.1',
      type: 'pkmsg',
      ciphertext: new Uint8Array([1]),
    })).resolves.toEqual(new Uint8Array([9]))

    const saveIdentitySpy = store.saveIdentity as ReturnType<typeof vi.fn>
    const decodeSpy = vi.spyOn(WhisperMessageEncoder, 'decodePreKeyWhisperMessage')
    decodeSpy.mockReturnValueOnce({ identityKey: 'bad' } as never)
    await expect(repo.decryptMessage({
      jid: 'bob.1',
      type: 'pkmsg',
      ciphertext: new Uint8Array([0x33, 0x01]),
    })).resolves.toEqual(new Uint8Array([9]))
    expect(saveIdentitySpy).not.toHaveBeenCalled()

    decodeSpy.mockImplementationOnce(() => { throw new Error('malformed-pkmsg') })
    await expect(repo.decryptMessage({
      jid: 'bob.1',
      type: 'pkmsg',
      ciphertext: new Uint8Array([0x33, 0x02]),
    })).resolves.toEqual(new Uint8Array([9]))

    saveIdentitySpy.mockResolvedValueOnce(false)
    decodeSpy.mockReturnValueOnce({ identityKey: new Uint8Array(32).fill(1) } as never)
    await expect(repo.decryptMessage({
      jid: 'bob.1',
      type: 'pkmsg',
      ciphertext: new Uint8Array([0x33, 0x03]),
    })).resolves.toEqual(new Uint8Array([9]))
    decodeSpy.mockRestore()

    // type msg path bypasses pkmsg extraction
    await expect(repo.decryptMessage({
      jid: 'bob.1',
      type: 'msg',
      ciphertext: new Uint8Array([9, 9, 9]),
    })).resolves.toEqual(new Uint8Array([8]))

    const firstEncrypt = await repo.encryptMessage({ jid: 'bob.1', data: new Uint8Array([1]) })
    const secondEncrypt = await repo.encryptMessage({ jid: 'bob.1', data: new Uint8Array([1]) })
    expect(firstEncrypt.type).toBe('pkmsg')
    expect(secondEncrypt.type).toBe('msg')

    expect(decryptPre).toHaveBeenCalled()
    expect(decryptMsg).toHaveBeenCalled()
    expect(encryptSpy).toHaveBeenCalledTimes(2)
  })

  it('covers runTxn fallback and sender-key initialization branches', async () => {
    const txStore = makeStore({
      transaction: vi.fn(async (run: () => Promise<unknown>) => run()),
      loadSenderKey: vi.fn(async (senderKeyName: { getSender: () => { toString: () => string } }) => {
        senderKeyName.getSender().toString()
        return ({}) as unknown as SenderKeyRecord
      }),
    })

    const processSpy = vi.spyOn(GroupSessionBuilder.prototype, 'process').mockResolvedValue(undefined)
    const createSpy = vi.spyOn(GroupSessionBuilder.prototype, 'create').mockResolvedValue(
      new SenderKeyDistributionMessage(9, 0, new Uint8Array(32).fill(4), new Uint8Array(33).fill(5))
    )
    const groupEncryptSpy = vi.spyOn(GroupCipher.prototype, 'encrypt').mockResolvedValue(new Uint8Array([7, 7, 7]))
    const groupDecryptSpy = vi.spyOn(GroupCipher.prototype, 'decrypt').mockResolvedValue(new Uint8Array([6, 6, 6]))

    const txRepo = makeLibSignalRepository(txStore)
    const distribution = new SenderKeyDistributionMessage(1, 0, new Uint8Array(32).fill(1), new Uint8Array(33).fill(2)).serialize()

    await txRepo.processSenderKeyDistributionMessage({
      groupId: 'g',
      authorJid: 'alice.1',
      axolotlSenderKeyDistributionMessage: distribution,
    })

    const groupResult = await txRepo.encryptGroupMessage({
      group: 'g',
      meId: 'alice.1',
      data: new Uint8Array([1, 2]),
    })
    expect(groupResult.ciphertext).toEqual(new Uint8Array([7, 7, 7]))

    const opened = await txRepo.decryptGroupMessage({ group: 'g', authorJid: 'alice.1', msg: new Uint8Array([8]) })
    expect(opened).toEqual(new Uint8Array([6, 6, 6]))

    expect(txStore.storeSenderKey).toHaveBeenCalled()
    expect(processSpy).toHaveBeenCalled()
    expect(createSpy).toHaveBeenCalled()
    expect(groupEncryptSpy).toHaveBeenCalled()
    expect(groupDecryptSpy).toHaveBeenCalled()

    // runTxn branch when store.transaction is absent.
    const noTxStore = makeStore()
    const initOutgoingSpy = vi.spyOn(SessionBuilder.prototype, 'initOutgoing').mockResolvedValue(undefined)
    const noTxRepo = makeLibSignalRepository(noTxStore)
    await noTxRepo.injectE2ESession({
      jid: 'plain-jid',
      session: {
        identityKey: new Uint8Array(32).fill(9),
        registrationId: 7,
        signedPreKey: {
          keyId: 1,
          publicKey: new Uint8Array(32).fill(8),
          signature: new Uint8Array(64).fill(7),
        },
      },
    })
    expect(initOutgoingSpy).toHaveBeenCalled()
  })

  it('covers validateSession/deleteSession/migrateSession branches', async () => {
    const existsOpen = new SessionRecord()
    const fakeOpen = {
      registrationId: 1,
      currentRatchet: {
        ephemeralKeyPair: { pubKey: new Uint8Array(32).fill(1), privKey: new Uint8Array(32).fill(2) },
        lastRemoteEphemeralKey: new Uint8Array(32).fill(3),
        previousCounter: 0,
        rootKey: new Uint8Array(32).fill(4),
      },
      indexInfo: {
        baseKey: new Uint8Array(32).fill(5),
        baseKeyType: 1,
        closed: -1,
        used: 1,
        created: 1,
        remoteIdentityKey: new Uint8Array(32).fill(6),
      },
      addChain: vi.fn(),
    } as unknown as Parameters<SessionRecord['setSession']>[0]
    existsOpen.setSession(fakeOpen)

    const noDeleteStore = makeStore({
      loadSession: vi.fn(async () => existsOpen),
    })
    const noDeleteRepo = makeLibSignalRepository(noDeleteStore)
    await expect(noDeleteRepo.deleteSession(['alice.1'])).rejects.toThrow('deleteSession is not supported by the provided store')
    await expect(noDeleteRepo.migrateSession('source.1', 'target.1')).resolves.toEqual({ migrated: 1, skipped: 0, total: 1 })

    const mixedStore = makeStore({
      deleteSession: vi.fn(async () => undefined),
      loadSession: vi.fn(async (addr: string) => {
        if (addr.includes('none')) return undefined
        if (addr.includes('closed')) {
          return { haveOpenSession: () => false } as unknown as SessionRecord
        }
        if (addr.includes('throw')) throw new Error('boom')
        return { haveOpenSession: () => true } as unknown as SessionRecord
      }),
    })
    const mixedRepo = makeLibSignalRepository(mixedStore)

    await expect(mixedRepo.validateSession('none.1')).resolves.toEqual({ exists: false, reason: 'no session' })
    await expect(mixedRepo.validateSession('closed.1')).resolves.toEqual({ exists: false, reason: 'no open session' })
    await expect(mixedRepo.validateSession('ok.1')).resolves.toEqual({ exists: true })
    await expect(mixedRepo.validateSession('throw.1')).resolves.toEqual({ exists: false, reason: 'validation error' })

    await mixedRepo.deleteSession(['a.1', 'b.1'])
    expect(mixedStore.deleteSession).toHaveBeenCalledTimes(2)

    await expect(mixedRepo.migrateSession('none.1', 'target.1')).resolves.toEqual({ migrated: 0, skipped: 1, total: 1 })
    await expect(mixedRepo.migrateSession('closed.1', 'target.1')).resolves.toEqual({ migrated: 0, skipped: 1, total: 1 })
    await expect(mixedRepo.migrateSession('ok.1', 'target.1')).resolves.toEqual({ migrated: 1, skipped: 0, total: 1 })
    expect(mixedStore.storeSession).toHaveBeenCalled()
  })
})

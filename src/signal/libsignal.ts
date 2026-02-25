import { ProtocolAddress } from '../protocol_address'
import { SessionBuilder } from '../session/builder/session-builder'
import type { PreKeyBundle } from '../session/builder/types'
import { SessionCipher } from '../session/cipher/session-cipher'
import type { SessionRecord } from '../session/record'
import type { SessionBuilderStorage } from '../session/builder/types'
import type { SessionCipherStorage } from '../session/cipher/types'
import { WhisperMessageEncoder } from '../session/cipher/encoding'
import {
    GroupCipher,
    GroupSessionBuilder,
    SenderKeyDistributionMessage,
    SenderKeyName,
    SenderKeyRecord,
    type SenderAddress
} from './group'

type MessageType = 'pkmsg' | 'msg'

interface LoggerLike {
    trace?(meta: unknown, message?: string): void
    debug?(meta: unknown, message?: string): void
    info?(meta: unknown, message?: string): void
    warn?(meta: unknown, message?: string): void
}

export interface SignalRepositoryStore extends SessionBuilderStorage, SessionCipherStorage {
    loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
    storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
    deleteSession?(addressName: string): Promise<void>
    saveIdentity?(addressName: string, identityKey: Uint8Array): Promise<boolean>
    transaction?<T>(run: () => Promise<T>, key: string): Promise<T>
}

export interface SignalRepositoryOptions {
    toProtocolAddress?: (jid: string) => ProtocolAddress
    logger?: LoggerLike
}

export interface SignalRepository {
    decryptGroupMessage(opts: { group: string; authorJid: string; msg: Uint8Array }): Promise<Uint8Array>
    processSenderKeyDistributionMessage(opts: {
        groupId: string
        authorJid: string
        axolotlSenderKeyDistributionMessage: Uint8Array
    }): Promise<void>
    decryptMessage(opts: { jid: string; type: MessageType; ciphertext: Uint8Array }): Promise<Uint8Array>
    encryptMessage(opts: { jid: string; data: Uint8Array }): Promise<{ type: MessageType; ciphertext: Uint8Array }>
    encryptGroupMessage(opts: { group: string; meId: string; data: Uint8Array }): Promise<{
        senderKeyDistributionMessage: Uint8Array
        ciphertext: Uint8Array
    }>
    injectE2ESession(opts: { jid: string; session: PreKeyBundle }): Promise<void>
    validateSession(jid: string): Promise<{ exists: boolean; reason?: string }>
    deleteSession(jids: string[]): Promise<void>
    migrateSession(fromJid: string, toJid: string): Promise<{ migrated: number; skipped: number; total: number }>
    jidToSignalProtocolAddress(jid: string): string
}

function defaultToProtocolAddress(jid: string): ProtocolAddress {
    if (jid.includes('.')) return ProtocolAddress.from(jid)
    return new ProtocolAddress(jid, 0)
}

function toSenderAddress(address: ProtocolAddress): SenderAddress {
    return {
        id: address.id,
        deviceId: address.deviceId,
        toString: () => address.toString()
    }
}

function tryExtractIdentityFromPkmsg(ciphertext: Uint8Array): Uint8Array | undefined {
    try {
        if (ciphertext.length < 2) return undefined
        const payload = WhisperMessageEncoder.decodePreKeyWhisperMessage(ciphertext.subarray(1))
        if (!(payload.identityKey instanceof Uint8Array)) return undefined
        return payload.identityKey
    } catch {
        return undefined
    }
}

export function makeLibSignalRepository(
    store: SignalRepositoryStore,
    options: SignalRepositoryOptions = {}
): SignalRepository {
    const toAddress = options.toProtocolAddress ?? defaultToProtocolAddress
    const logger = options.logger

    const runTxn = async <T>(key: string, run: () => Promise<T>): Promise<T> => {
        if (!store.transaction) return run()
        return store.transaction(run, key)
    }

    const jidToSignalProtocolAddress = (jid: string): ProtocolAddress => toAddress(jid)
    const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
        const addr = jidToSignalProtocolAddress(user)
        return new SenderKeyName(group, toSenderAddress(addr))
    }

    return {
        decryptGroupMessage({ group, authorJid, msg }) {
            const senderName = jidToSignalSenderKeyName(group, authorJid)
            const cipher = new GroupCipher(store, senderName)
            return runTxn(group, async () => cipher.decrypt(msg))
        },

        async processSenderKeyDistributionMessage({ groupId, authorJid, axolotlSenderKeyDistributionMessage }) {
            const builder = new GroupSessionBuilder(store)
            const senderName = jidToSignalSenderKeyName(groupId, authorJid)

            return runTxn(groupId, async () => {
                const current = await store.loadSenderKey(senderName)
                if (!(current instanceof SenderKeyRecord)) {
                    await store.storeSenderKey(senderName, new SenderKeyRecord())
                }

                const senderMsg = new SenderKeyDistributionMessage(
                    undefined,
                    undefined,
                    undefined,
                    undefined,
                    axolotlSenderKeyDistributionMessage
                )
                await builder.process(senderName, senderMsg)
            })
        },

        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToSignalProtocolAddress(jid)
            const session = new SessionCipher(store, addr)

            if (type === 'pkmsg') {
                const identity = tryExtractIdentityFromPkmsg(ciphertext)
                if (identity && store.saveIdentity) {
                    const changed = await store.saveIdentity(addr.toString(), identity)
                    if (changed) {
                        logger?.info?.({ jid, addr: addr.toString() }, 'identity key changed')
                    }
                }
            }

            return runTxn(jid, async () => {
                if (type === 'pkmsg') return session.decryptPreKeyWhisperMessage(ciphertext)
                return session.decryptWhisperMessage(ciphertext)
            })
        },

        async encryptMessage({ jid, data }) {
            const addr = jidToSignalProtocolAddress(jid)
            const cipher = new SessionCipher(store, addr)

            return runTxn(jid, async () => {
                const { type, body } = await cipher.encrypt(data)
                return { type: type === 3 ? 'pkmsg' : 'msg', ciphertext: body }
            })
        },

        async encryptGroupMessage({ group, meId, data }) {
            const senderName = jidToSignalSenderKeyName(group, meId)
            const builder = new GroupSessionBuilder(store)

            return runTxn(group, async () => {
                const current = await store.loadSenderKey(senderName)
                if (!(current instanceof SenderKeyRecord)) {
                    await store.storeSenderKey(senderName, new SenderKeyRecord())
                }

                const senderKeyDistributionMessage = await builder.create(senderName)
                const session = new GroupCipher(store, senderName)
                const ciphertext = await session.encrypt(data)
                return {
                    ciphertext,
                    senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
                }
            })
        },

        async injectE2ESession({ jid, session }) {
            logger?.trace?.({ jid }, 'injecting E2EE session')
            const builder = new SessionBuilder(store, jidToSignalProtocolAddress(jid))
            await runTxn(jid, async () => builder.initOutgoing(session))
        },

        jidToSignalProtocolAddress(jid) {
            return jidToSignalProtocolAddress(jid).toString()
        },

        async validateSession(jid: string) {
            try {
                const addr = jidToSignalProtocolAddress(jid)
                const session = await store.loadSession(addr.toString())
                if (!session) return { exists: false, reason: 'no session' }
                if (!session.haveOpenSession()) return { exists: false, reason: 'no open session' }
                return { exists: true }
            } catch {
                return { exists: false, reason: 'validation error' }
            }
        },

        async deleteSession(jids: string[]) {
            if (!store.deleteSession) {
                throw new Error('deleteSession is not supported by the provided store')
            }
            await runTxn(`delete-${jids.length}`, async () => {
                for (let i = 0; i < jids.length; i++) {
                    const addr = jidToSignalProtocolAddress(jids[i]!)
                    await store.deleteSession!(addr.toString())
                }
            })
        },

        async migrateSession(fromJid: string, toJid: string) {
            const fromAddr = jidToSignalProtocolAddress(fromJid).toString()
            const toAddr = jidToSignalProtocolAddress(toJid).toString()

            return runTxn(`migrate-${fromAddr}->${toAddr}`, async () => {
                const session = await store.loadSession(fromAddr)
                if (!session || !session.haveOpenSession()) {
                    return { migrated: 0, skipped: 1, total: 1 }
                }

                await store.storeSession(toAddr, session)
                if (store.deleteSession) {
                    await store.deleteSession(fromAddr)
                }
                return { migrated: 1, skipped: 0, total: 1 }
            })
        }
    }
}

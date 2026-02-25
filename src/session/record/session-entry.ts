import { assertUint8, toBase64, fromBase64, u8 } from '../utils'
import type {
    ChainState,
    CurrentRatchet,
    IndexInfo,
    PendingPreKey,
    SerializedChainState,
    SerializedPendingPreKey,
    SerializedSessionEntry,
} from './types'

export class SessionEntry {
    registrationId!: number
    currentRatchet!: CurrentRatchet
    indexInfo!: IndexInfo
    pendingPreKey?: PendingPreKey

    private _chains = new Map<string, ChainState>()

    toString(): string {
        const baseKey = this.indexInfo?.baseKey ? toBase64(this.indexInfo.baseKey) : '—'
        return `<SessionEntry [baseKey=${baseKey}]>`
    }

    inspect(): string {
        return this.toString()
    }

    clone(): SessionEntry {
        return SessionEntry.deserialize(this.serialize())
    }

    replaceWith(snapshot: SessionEntry): void {
        const next = SessionEntry.deserialize(snapshot.serialize())
        this.registrationId = next.registrationId
        this.currentRatchet = next.currentRatchet
        this.indexInfo = next.indexInfo
        if (next.pendingPreKey) {
            this.pendingPreKey = next.pendingPreKey
        } else {
            delete this.pendingPreKey
        }
        this._chains = next._chains
    }

    addChain(key: Uint8Array, value: ChainState): void {
        assertUint8(key)
        const id = toBase64(key)
        if (this._chains.has(id)) throw new Error('Overwrite attempt')
        this._chains.set(id, value)
    }

    getChain(key: Uint8Array): ChainState | undefined {
        assertUint8(key)
        return this._chains.get(toBase64(key))
    }

    deleteChain(key: Uint8Array): void {
        assertUint8(key)
        const id = toBase64(key)
        if (!this._chains.has(id)) throw new ReferenceError('Not Found')
        this._chains.delete(id)
    }

    *chains(): Generator<[Uint8Array, ChainState]> {
        for (const [k, v] of this._chains) {
            yield [fromBase64(k), v]  // fromBase64 importado abaixo
        }
    }

    /* ==================== Serialization ==================== */

    private serializeChains(): Record<string, SerializedChainState> {
        const result: Record<string, SerializedChainState> = {}
        for (const [key, c] of this._chains) {
            if (!c) continue
            const messageKeys: Record<string, string> = {}
            for (const [idx, mk] of c.messageKeys) {
                messageKeys[String(idx)] = u8.encode(mk)!
            }
            result[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: u8.encode(c.chainKey.key),
                },
                chainType: c.chainType,
                messageKeys,
            }
        }
        return result
    }

    private serializePendingPreKey(ppk: PendingPreKey): SerializedPendingPreKey {
        return {
            baseKey: u8.encode(ppk.baseKey)!,
            signedKeyId: ppk.signedKeyId,
            ...(ppk.preKeyId !== undefined && { preKeyId: ppk.preKeyId }),
        }
    }

    serialize(): SerializedSessionEntry {
        const data: SerializedSessionEntry = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: u8.encode(this.currentRatchet.ephemeralKeyPair.pubKey)!,
                    privKey: u8.encode(this.currentRatchet.ephemeralKeyPair.privKey)!,
                },
                lastRemoteEphemeralKey: u8.encode(this.currentRatchet.lastRemoteEphemeralKey)!,
                previousCounter: this.currentRatchet.previousCounter,
                rootKey: u8.encode(this.currentRatchet.rootKey)!,
            },
            indexInfo: {
                baseKey: u8.encode(this.indexInfo.baseKey)!,
                baseKeyType: this.indexInfo.baseKeyType,
                closed: this.indexInfo.closed,
                used: this.indexInfo.used,
                created: this.indexInfo.created,
                remoteIdentityKey: u8.encode(this.indexInfo.remoteIdentityKey)!,
            },
            _chains: this.serializeChains(),
        }

        if (this.pendingPreKey) {
            data.pendingPreKey = this.serializePendingPreKey(this.pendingPreKey)
        }
        return data
    }

    private static deserializeChains(chains: Record<string, SerializedChainState>): Map<string, ChainState> {
        const result = new Map<string, ChainState>()
        for (const [key, c] of Object.entries(chains)) {
            if (!c) continue
            const messageKeys = new Map<number, Uint8Array>()
            for (const [idx, mk] of Object.entries(c.messageKeys)) {
                messageKeys.set(Number(idx), u8.decode(mk)!)
            }
            result.set(key, {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: u8.decode(c.chainKey.key),
                },
                chainType: c.chainType,
                messageKeys,
            })
        }
        return result
    }

    private static deserializePendingPreKey(data: SerializedPendingPreKey): PendingPreKey {
        // - Safer deserialization without unsafe non-null assertions
        return {
            baseKey: u8.decode(data.baseKey)!,
            signedKeyId: data.signedKeyId,
            ...(data.preKeyId !== undefined && { preKeyId: data.preKeyId }),
        }
    }

    static deserialize(data: SerializedSessionEntry): SessionEntry {
        const obj = new SessionEntry()

        obj.registrationId = data.registrationId
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: u8.decode(data.currentRatchet.ephemeralKeyPair.pubKey)!,
                privKey: u8.decode(data.currentRatchet.ephemeralKeyPair.privKey)!,
            },
            lastRemoteEphemeralKey: u8.decode(data.currentRatchet.lastRemoteEphemeralKey)!,
            previousCounter: data.currentRatchet.previousCounter,
            rootKey: u8.decode(data.currentRatchet.rootKey)!,
        }
        obj.indexInfo = {
            baseKey: u8.decode(data.indexInfo.baseKey)!,
            baseKeyType: data.indexInfo.baseKeyType,
            closed: data.indexInfo.closed,
            used: data.indexInfo.used,
            created: data.indexInfo.created,
            remoteIdentityKey: u8.decode(data.indexInfo.remoteIdentityKey)!,
        }
        obj._chains = this.deserializeChains(data._chains)

        if (data.pendingPreKey) {
            obj.pendingPreKey = this.deserializePendingPreKey(data.pendingPreKey)
        }

        return obj
    }
}

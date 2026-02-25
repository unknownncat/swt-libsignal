import type { BaseKeyType, ChainType } from "../../ratchet-types"

export interface PendingPreKey {
    baseKey: Uint8Array
    signedKeyId: number
    preKeyId?: number
}

export interface ChainKey {
    counter: number
    key: Uint8Array | undefined
}

export interface ChainState {
    chainKey: ChainKey
    chainType: ChainType  // - Use ChainType enum
    messageKeys: Map<number, Uint8Array>
}

export interface CurrentRatchet {
    ephemeralKeyPair: {
        pubKey: Uint8Array
        privKey: Uint8Array
    }
    lastRemoteEphemeralKey: Uint8Array
    previousCounter: number
    rootKey: Uint8Array
}

export interface IndexInfo {
    baseKey: Uint8Array
    baseKeyType: BaseKeyType
    closed: number
    used: number
    created: number
    remoteIdentityKey: Uint8Array
}

/* ====================== Serialized ====================== */

export interface SerializedChainState {
    chainKey: {
        counter: number
        key: string | undefined
    }
    chainType: ChainType  // - Use ChainType enum
    messageKeys: Record<string, string>
}

export interface SerializedPendingPreKey {
    baseKey: string
    signedKeyId: number
    preKeyId?: number
}

export interface SerializedSessionEntry {
    registrationId: number
    currentRatchet: {
        ephemeralKeyPair: { pubKey: string; privKey: string }
        lastRemoteEphemeralKey: string
        previousCounter: number
        rootKey: string
    }
    indexInfo: {
        baseKey: string
        baseKeyType: BaseKeyType
        closed: number
        used: number
        created: number
        remoteIdentityKey: string
    }
    _chains: Record<string, SerializedChainState>
    pendingPreKey?: SerializedPendingPreKey
}

export interface SerializedSessionRecord {
    _sessions: Record<string, SerializedSessionEntry>
    version: string
}

import type { SessionRecord, SessionEntry, PendingPreKey } from '../record/index'
import type { MaybePromise } from '../storage/types'

export interface PreKeyWhisperMessage {
    identityKey: Uint8Array
    registrationId: number
    baseKey: Uint8Array
    signedPreKeyId: number
    preKeyId?: number
    message: Uint8Array
}

export interface IdentityKeyPair {
    pubKey: Uint8Array
    privKey: Uint8Array
}

export type KeyPair = {
    pubKey: Uint8Array
    privKey: Uint8Array
}

export interface PreKeyBundle {
    identityKey: Uint8Array
    registrationId: number
    preKey?: {
        keyId: number
        publicKey: Uint8Array
    }
    signedPreKey: {
        keyId: number
        publicKey: Uint8Array
        signature: Uint8Array
    }
}

export interface SessionBuilderStorage {
    isTrustedIdentity(addressName: string, identityKey: Uint8Array): MaybePromise<boolean>
    loadSession(addressName: string): MaybePromise<SessionRecord | undefined>
    storeSession(addressName: string, record: SessionRecord): MaybePromise<void>
    getOurIdentity(): MaybePromise<IdentityKeyPair>
    loadPreKey(preKeyId: number): MaybePromise<KeyPair | undefined>
    loadSignedPreKey(signedPreKeyId: number): MaybePromise<KeyPair | undefined>
    loadPreKeyPair?(preKeyId: number | undefined, signedPreKeyId: number): MaybePromise<readonly [KeyPair | undefined, KeyPair | undefined]>
}
import type { MaybePromise } from '../storage/types'
import type { SessionEntry } from "../record/session-entry"
import type { SessionRecord } from "../record/session-record"
import type { CompatMode } from '../builder/types'
import type { CryptoSuite } from './crypto-suite'

export interface EncryptResult {
    type: number
    body: Uint8Array
    registrationId: number
}

export interface DecryptResult {
    plaintext: Uint8Array
}

export interface DecryptWithSessionResult {
    session: SessionEntry
    plaintext: Uint8Array
}

export interface WhisperMessageProto {
    ephemeralKey: Uint8Array
    counter: number
    previousCounter: number
    ciphertext: Uint8Array
}

export interface PreKeyWhisperMessageProto {
    identityKey: Uint8Array
    registrationId: number
    baseKey: Uint8Array
    signedPreKeyId: number
    preKeyId?: number
    message: Uint8Array
}

export interface SessionCipherStorage {
    loadSession(addressName: string): MaybePromise<SessionRecord | undefined>
    storeSession(addressName: string, record: SessionRecord): MaybePromise<void>
    getOurIdentity(): MaybePromise<{ pubKey: Uint8Array; privKey: Uint8Array }>
    isTrustedIdentity(addressName: string, identityKey: Uint8Array): MaybePromise<boolean>
    getOurRegistrationId(): MaybePromise<number>
    loadPreKey(preKeyId: number): MaybePromise<{ pubKey: Uint8Array; privKey: Uint8Array } | undefined>
    loadSignedPreKey(signedPreKeyId: number): MaybePromise<{ pubKey: Uint8Array; privKey: Uint8Array } | undefined>
    removePreKey(preKeyId: number): MaybePromise<void>
    storeSessionAndRemovePreKey?(addressName: string, record: SessionRecord, preKeyId: number): MaybePromise<void>
    loadPreKeyPair?(preKeyId: number | undefined, signedPreKeyId: number): MaybePromise<readonly [{ pubKey: Uint8Array; privKey: Uint8Array } | undefined, { pubKey: Uint8Array; privKey: Uint8Array } | undefined]>
}

export interface SessionCipherOptions {
    compatMode?: CompatMode
    cryptoSuite?: CryptoSuite
    warn?: (message: string) => void
}

import { SessionRecord } from '../record/index'
import { fromBase64, toBase64 } from '../utils'
import type { MaybePromise, StorageAdapter } from './types'
import { deleteValue, getMany, getValue, setMany, setValue } from './runtime'

function sessionKey(addr: string) { return `session:${addr}` }
function preKeyKey(id: number) { return `prekey:${id}` }
function signedPreKeyKey(id: number) { return `signedprekey:${id}` }
function identityKeyF(addr: string) { return `identity:${addr}` }
const OUR_IDENTITY = 'our_identity'
const REG_ID = 'registration_id'

type SerializedRecord = ReturnType<SessionRecord['serialize']>
type IdentityTuple = readonly [pubKey: Uint8Array, privKey: Uint8Array]

type LegacyIdentityValue = { readonly pubKey: string; readonly privKey: string }
type IdentityValue = { readonly pubKey: Uint8Array; readonly privKey: Uint8Array }

function decodeIdentity(value: IdentityValue | LegacyIdentityValue | undefined): IdentityTuple | undefined {
    if (!value) return undefined
    if (value.pubKey instanceof Uint8Array && value.privKey instanceof Uint8Array) {
        return [value.pubKey, value.privKey]
    }
    if (typeof value.pubKey !== 'string' || typeof value.privKey !== 'string') {
        throw new TypeError('Invalid identity storage shape')
    }
    return [fromBase64(value.pubKey), fromBase64(value.privKey)]
}

function maybeAwait<T>(value: MaybePromise<T>): Promise<T> {
    return Promise.resolve(value)
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) {
        diff |= a[i]! ^ b[i]!
    }
    return diff === 0
}

export function createSessionStorage(adapter: StorageAdapter<unknown>) {
    return {
        async isTrustedIdentity(addressName: string, identityKey: Uint8Array): Promise<boolean> {
            const key = identityKeyF(addressName)
            const stored = await maybeAwait(getValue(adapter, key) as MaybePromise<Uint8Array | string | undefined>)

            if (!stored) {
                await maybeAwait(setValue(adapter, key, identityKey))
                return true
            }

            const storedBytes = stored instanceof Uint8Array ? stored : fromBase64(stored)
            return constantTimeEqual(storedBytes, identityKey)
        },

        async loadSession(addressName: string): Promise<SessionRecord | undefined> {
            const data = await maybeAwait(getValue(adapter, sessionKey(addressName)) as MaybePromise<SerializedRecord | undefined>)
            if (!data) return undefined
            return SessionRecord.deserialize(data)
        },

        async storeSession(addressName: string, record: SessionRecord): Promise<void> {
            await maybeAwait(setValue(adapter, sessionKey(addressName), record.serialize()))
        },

        async getOurIdentity(): Promise<{ pubKey: Uint8Array; privKey: Uint8Array }> {
            const value = await maybeAwait(getValue(adapter, OUR_IDENTITY) as MaybePromise<IdentityValue | LegacyIdentityValue | undefined>)
            const tuple = decodeIdentity(value)
            if (!tuple) throw new Error('Our identity not found in storage')
            return { pubKey: tuple[0], privKey: tuple[1] }
        },

        async loadPreKey(preKeyId: number): Promise<{ pubKey: Uint8Array; privKey: Uint8Array } | undefined> {
            const value = await maybeAwait(getValue(adapter, preKeyKey(preKeyId)) as MaybePromise<IdentityValue | LegacyIdentityValue | undefined>)
            const tuple = decodeIdentity(value)
            if (!tuple) return undefined
            return { pubKey: tuple[0], privKey: tuple[1] }
        },

        async loadSignedPreKey(signedPreKeyId: number): Promise<{ pubKey: Uint8Array; privKey: Uint8Array } | undefined> {
            const value = await maybeAwait(getValue(adapter, signedPreKeyKey(signedPreKeyId)) as MaybePromise<IdentityValue | LegacyIdentityValue | undefined>)
            const tuple = decodeIdentity(value)
            if (!tuple) return undefined
            return { pubKey: tuple[0], privKey: tuple[1] }
        },

        async loadPreKeyPair(preKeyId: number | undefined, signedPreKeyId: number): Promise<readonly [
            { pubKey: Uint8Array; privKey: Uint8Array } | undefined,
            { pubKey: Uint8Array; privKey: Uint8Array } | undefined
        ]> {
            const keys = preKeyId == null
                ? [signedPreKeyKey(signedPreKeyId)] as const
                : [preKeyKey(preKeyId), signedPreKeyKey(signedPreKeyId)] as const
            const values = await maybeAwait(getMany(adapter, keys, { prefetch: true, cacheHint: 'hot' }))

            if (preKeyId == null) {
                const signed = decodeIdentity(values[0] as IdentityValue | LegacyIdentityValue | undefined)
                return [undefined, signed ? { pubKey: signed[0], privKey: signed[1] } : undefined]
            }

            const pre = decodeIdentity(values[0] as IdentityValue | LegacyIdentityValue | undefined)
            const signed = decodeIdentity(values[1] as IdentityValue | LegacyIdentityValue | undefined)
            return [
                pre ? { pubKey: pre[0], privKey: pre[1] } : undefined,
                signed ? { pubKey: signed[0], privKey: signed[1] } : undefined
            ]
        },

        async primeSession(addressName: string): Promise<void> {
            await maybeAwait(adapter.prefetch?.([sessionKey(addressName), identityKeyF(addressName), OUR_IDENTITY]) ?? undefined)
        },

        async storeSessionAndRemovePreKey(addressName: string, record: SessionRecord, preKeyId: number): Promise<void> {
            await maybeAwait(setValue(adapter, sessionKey(addressName), record.serialize()))
            await maybeAwait(deleteValue(adapter, preKeyKey(preKeyId)))
            await maybeAwait(adapter.zeroize?.(preKeyKey(preKeyId)) ?? undefined)
        },

        async removePreKey(preKeyId: number): Promise<void> {
            await maybeAwait(deleteValue(adapter, preKeyKey(preKeyId)))
            await maybeAwait(adapter.zeroize?.(preKeyKey(preKeyId)) ?? undefined)
        },

        async storeBootstrap(identity: { readonly pubKey: Uint8Array; readonly privKey: Uint8Array }, registrationId: number): Promise<void> {
            await maybeAwait(setMany(adapter, [
                { key: OUR_IDENTITY, value: { pubKey: identity.pubKey, privKey: identity.privKey } },
                { key: REG_ID, value: registrationId }
            ]))
        },

        async getOurRegistrationId(): Promise<number> {
            const v = await maybeAwait(getValue(adapter, REG_ID) as MaybePromise<number | undefined>)
            if (typeof v !== 'number') throw new Error('registration id missing')
            return v
        },

        async migrateLegacyIdentityStorage(addressName: string, identityKey: Uint8Array): Promise<void> {
            await maybeAwait(setValue(adapter, identityKeyF(addressName), toBase64(identityKey)))
        }
    }
}

/** @stable Generic brand helper for opaque identifiers. */
export type Brand<T, B extends string> = T & { readonly __brand: B }

/** @stable Branded protocol address ID string. */
export type AddressId = Brand<string, 'AddressId'>
/** @stable Branded storage key. */
export type StorageKey = Brand<string, 'StorageKey'>

/** @stable */
export { ProtocolAddress } from '../protocol_address'
/** @stable */
export {
    generateIdentityKeyPair,
    generateRegistrationId,
    generateSignedPreKey,
    generatePreKey,
} from '../key-helper'
export {
    generateIdentityKeyPairAsync,
    generateRegistrationIdAsync,
    generateSignedPreKeyAsync,
    generatePreKeyAsync,
} from '../key-helper-async'
export type { SignedPreKey, PreKey } from '../key-helper'
export { FingerprintGenerator } from '../fingerprint'

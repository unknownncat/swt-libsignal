import { randomBytes } from 'node:crypto'
import * as curve from './curve'

function isNonNegativeInteger(value: unknown): value is number {
    return typeof value === 'number' && Number.isInteger(value) && value >= 0
}

export const generateIdentityKeyPair = curve.generateKeyPair

export function generateRegistrationId(): number {
    const bytes = randomBytes(2)
    return (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) & 0x3fff
}

export function generateSignedPreKey(
    identityKeyPair: { readonly pubKey: Buffer; readonly privKey: Buffer },
    signedKeyId: number
): { keyId: number; keyPair: { pubKey: Buffer; privKey: Buffer }; signature: Buffer } {
    if (
        !(identityKeyPair.privKey instanceof Buffer) ||
        identityKeyPair.privKey.byteLength !== 32 ||
        !(identityKeyPair.pubKey instanceof Buffer) ||
        identityKeyPair.pubKey.byteLength !== 33
    ) {
        throw new TypeError('Invalid argument for identityKeyPair')
    }
    if (!isNonNegativeInteger(signedKeyId)) {
        throw new TypeError(`Invalid argument for signedKeyId: ${signedKeyId}`)
    }

    const keyPair = curve.generateKeyPair()
    const signature = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey)
    return {
        keyId: signedKeyId,
        keyPair,
        signature
    }
}

export function generatePreKey(keyId: number): {
    keyId: number
    keyPair: { pubKey: Buffer; privKey: Buffer }
} {
    if (!isNonNegativeInteger(keyId)) {
        throw new TypeError(`Invalid argument for keyId: ${keyId}`)
    }
    return {
        keyId,
        keyPair: curve.generateKeyPair()
    }
}


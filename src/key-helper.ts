// key-helper.ts

import { randomBytes } from 'crypto'
import type {
    IdentityKeyPair,
    DHKeyPair
} from './types/asymmetric'

import * as curve from './curve'

export interface SignedPreKey {
    keyId: number
    keyPair: DHKeyPair
    signature: Uint8Array
}

export interface PreKey {
    keyId: number
    keyPair: DHKeyPair
}

function isNonNegativeInteger(n: unknown): n is number {
    return (
        typeof n === 'number' &&
        Number.isInteger(n) &&
        n >= 0
    )
}

// Identity

export const generateIdentityKeyPair = curve.signalCrypto.generateIdentityKeyPair

// Registration ID (14 bits)

export function generateRegistrationId(): number {
    const bytes = randomBytes(2)
    // Fast bitwise operation to get 14-bit value
    return (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) & 0x3fff
}

// Signed Pre Key

export async function generateSignedPreKey(
    identityKeyPair: IdentityKeyPair,
    signedKeyId: number
): Promise<SignedPreKey> {

    if (
        !(identityKeyPair.privateKey instanceof Uint8Array) ||
        identityKeyPair.privateKey.length !== 64
    ) {
        throw new TypeError('Invalid Ed25519 private key')
    }

    if (
        !(identityKeyPair.publicKey instanceof Uint8Array) ||
        identityKeyPair.publicKey.length !== 32
    ) {
        throw new TypeError('Invalid Ed25519 public key')
    }

    if (!isNonNegativeInteger(signedKeyId)) {
        throw new TypeError(
            `Invalid argument for signedKeyId: ${signedKeyId}`
        )
    }

    // DH key (X25519)
    const keyPair = await curve.generateKeyPair()

    // Assina a publicKey X25519 usando Ed25519
    const signature = curve.calculateSignature(
        identityKeyPair.privateKey,
        keyPair.publicKey
    )

    return {
        keyId: signedKeyId,
        keyPair,
        signature
    }
}

// Pre Key

export async function generatePreKey(
    keyId: number
): Promise<PreKey> {

    if (!isNonNegativeInteger(keyId)) {
        throw new TypeError(
            `Invalid argument for keyId: ${keyId}`
        )
    }

    const keyPair = await curve.generateKeyPair()

    return {
        keyId,
        keyPair
    }
}

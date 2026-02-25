import libsodium from 'libsodium-wrappers'
import type { IdentityKeyPair, DHKeyPair, SignalAsymmetricAPI } from './types/asymmetric'
import {
    asEd25519PublicKey,
    asEd25519SecretKey,
    asX25519PublicKey,
    asX25519SecretKey
} from './types/branded'
import type { X25519PublicKey, X25519SecretKey } from './types/branded'

let sodiumReadyPromise: Promise<void> | null = null
let sodiumInitialized = false

export async function initCrypto(): Promise<void> {
    if (!sodiumReadyPromise) {
        sodiumReadyPromise = libsodium.ready.then(() => {
            sodiumInitialized = true
        })
    }
    await sodiumReadyPromise
}

function assertReady(): void {
    if (!sodiumInitialized) {
        throw new Error('libsodium is not initialized. Call initCrypto() before using synchronous crypto operations.')
    }
}

function assertLength(data: Uint8Array, expected: number, name: string) {
    if (data.length !== expected) {
        throw new Error(`${name} must be ${expected} bytes`)
    }
}

async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
    await initCrypto()

    const kp = libsodium.crypto_sign_keypair()

    return {
        publicKey: asEd25519PublicKey(kp.publicKey),
        privateKey: asEd25519SecretKey(kp.privateKey)
    }
}

function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    assertReady()
    const edSk = asEd25519SecretKey(privateKey)

    return libsodium.crypto_sign_detached(message, edSk)
}

function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    assertReady()
    const edPk = asEd25519PublicKey(publicKey)
    assertLength(signature, 64, 'Signature')

    return libsodium.crypto_sign_verify_detached(signature, message, edPk)
}

async function generateDHKeyPair(): Promise<DHKeyPair> {
    await initCrypto()

    const kp = libsodium.crypto_kx_keypair()

    return {
        publicKey: asX25519PublicKey(kp.publicKey),
        privateKey: asX25519SecretKey(kp.privateKey)
    }
}

function calculateAgreement(publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array {
    assertReady()
    const xPk = asX25519PublicKey(publicKey)
    const xSk = asX25519SecretKey(privateKey)

    return libsodium.crypto_scalarmult(xSk, xPk)
}

function convertIdentityPublicToX25519(edPublicKey: Uint8Array): X25519PublicKey {
    assertReady()
    const edPk = asEd25519PublicKey(edPublicKey)

    return asX25519PublicKey(libsodium.crypto_sign_ed25519_pk_to_curve25519(edPk))
}

function convertIdentityPrivateToX25519(edPrivateKey: Uint8Array): X25519SecretKey {
    assertReady()
    const edSk = asEd25519SecretKey(edPrivateKey)

    return asX25519SecretKey(libsodium.crypto_sign_ed25519_sk_to_curve25519(edSk))
}

async function generateKeyPair() {
    return generateDHKeyPair()
}

function calculateSignature(identityPrivateKey: Uint8Array, data: Uint8Array) {
    return sign(identityPrivateKey, data)
}

export const signalCrypto: SignalAsymmetricAPI = {
    generateIdentityKeyPair,
    sign,
    verify,
    generateDHKeyPair,
    calculateAgreement,
    convertIdentityPublicToX25519,
    convertIdentityPrivateToX25519
}

export { generateKeyPair, calculateSignature }
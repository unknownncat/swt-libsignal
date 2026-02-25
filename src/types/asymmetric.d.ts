import type { Ed25519PublicKey, Ed25519SecretKey, X25519PublicKey, X25519SecretKey } from './branded'

export interface IdentityKeyPair {
    readonly publicKey: Ed25519PublicKey
    readonly privateKey: Ed25519SecretKey
}

export interface DHKeyPair {
    readonly publicKey: X25519PublicKey
    readonly privateKey: X25519SecretKey
}

export interface SignalAsymmetricAPI {
    /* Identity (Ed25519) */
    generateIdentityKeyPair(): Promise<IdentityKeyPair>
    sign(privateKey: Ed25519SecretKey | Uint8Array, message: Uint8Array): Uint8Array
    verify(publicKey: Ed25519PublicKey | Uint8Array, message: Uint8Array, signature: Uint8Array): boolean

    /* DH (X25519) */
    generateDHKeyPair(): Promise<DHKeyPair>
    calculateAgreement(publicKey: X25519PublicKey | Uint8Array, privateKey: X25519SecretKey | Uint8Array): Uint8Array

    /* Conversion */
    convertIdentityPublicToX25519(edPublicKey: Ed25519PublicKey | Uint8Array): X25519PublicKey
    convertIdentityPrivateToX25519(edPrivateKey: Ed25519SecretKey | Uint8Array): X25519SecretKey
}

export const signalCrypto: SignalAsymmetricAPI
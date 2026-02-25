export interface CipherResult {
    readonly ciphertext: Uint8Array
    readonly iv: Uint8Array
    readonly tag: Uint8Array
}

export interface EncryptOptions {
    readonly aad?: Uint8Array
    readonly iv?: Uint8Array
}

export interface DecryptOptions {
    readonly aad?: Uint8Array
}

export interface HKDFOptions {
    readonly length: number
}

/**
 * High-level cryptographic API
 */
export interface CryptoAPI {
    /**
     * AES-256-GCM encryption
     */
    encrypt(
        key: Uint8Array,
        plaintext: Uint8Array,
        options?: EncryptOptions
    ): CipherResult

    /**
     * AES-256-GCM decryption
     */
    decrypt(
        key: Uint8Array,
        data: CipherResult,
        options?: DecryptOptions
    ): Uint8Array

    /**
     * HKDF using HMAC-SHA256
     */
    hkdf(
        ikm: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        options: HKDFOptions
    ): Uint8Array

    /**
     * SHA-512 digest
     */
    sha512(data: Uint8Array): Uint8Array

    /**
     * HMAC-SHA256
     */
    hmacSha256(
        key: Uint8Array,
        data: Uint8Array
    ): Uint8Array
}

/** API assíncrona equivalente para workloads não bloqueantes. */
export interface CryptoAsyncAPI {
    encrypt(
        key: Uint8Array,
        plaintext: Uint8Array,
        options?: EncryptOptions
    ): Promise<CipherResult>
    decrypt(
        key: Uint8Array,
        data: CipherResult,
        options?: DecryptOptions
    ): Promise<Uint8Array>
    hkdf(
        ikm: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        options: HKDFOptions
    ): Promise<Uint8Array>
    sha512(data: Uint8Array): Promise<Uint8Array>
    hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>
}

/**
 * Default Node implementation
 */
export const crypto: CryptoAPI
export const cryptoAsync: CryptoAsyncAPI

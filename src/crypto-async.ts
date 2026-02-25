import { randomBytes, webcrypto } from 'node:crypto'

import type { CipherResult, DecryptOptions, EncryptOptions, HKDFOptions } from './types/crypto'

const subtle = webcrypto.subtle
const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_LENGTH = 32

function concatBytes(parts: Uint8Array[]): Uint8Array {
    const size = parts.reduce((acc, part) => acc + part.length, 0)
    const out = new Uint8Array(size)
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function splitCiphertextAndTag(value: Uint8Array): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (value.length < TAG_LENGTH) {
        throw new Error('Ciphertext payload must include a 16-byte tag')
    }

    const ciphertext = value.subarray(0, value.length - TAG_LENGTH)
    const tag = value.subarray(value.length - TAG_LENGTH)
    return { ciphertext, tag }
}

function toBufferSource(data: Uint8Array): Uint8Array {
    return data
}

async function randomBytesAsync(size: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        randomBytes(size, (error, buffer) => {
            if (error) {
                reject(error)
                return
            }
            resolve(new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength))
        })
    })
}

export async function encryptAsync(
    key: Uint8Array,
    plaintext: Uint8Array,
    options?: EncryptOptions
): Promise<CipherResult> {
    if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes')

    const iv = options?.iv ?? await randomBytesAsync(IV_LENGTH)
    if (iv.length !== IV_LENGTH) throw new Error('IV must be 12 bytes for AES-GCM')

    const cryptoKey = await subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['encrypt'])
    const encrypted = await subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: toBufferSource(iv),
            additionalData: options?.aad ? toBufferSource(options.aad) : undefined,
            tagLength: TAG_LENGTH * 8
        },
        cryptoKey,
        toBufferSource(plaintext)
    )

    const result = new Uint8Array(encrypted)
    const { ciphertext, tag } = splitCiphertextAndTag(result)
    return { ciphertext, iv, tag }
}

export async function decryptAsync(
    key: Uint8Array,
    data: CipherResult,
    options?: DecryptOptions
): Promise<Uint8Array> {
    if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes')
    if (data.iv.length !== IV_LENGTH) throw new Error('IV must be 12 bytes for AES-GCM')
    if (data.tag.length !== TAG_LENGTH) throw new Error('Tag must be 16 bytes for AES-GCM')

    const payload = concatBytes([data.ciphertext, data.tag])
    const cryptoKey = await subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['decrypt'])
    const decrypted = await subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: toBufferSource(data.iv),
            additionalData: options?.aad ? toBufferSource(options.aad) : undefined,
            tagLength: TAG_LENGTH * 8
        },
        cryptoKey,
        toBufferSource(payload)
    )

    return new Uint8Array(decrypted)
}

export async function sha512Async(data: Uint8Array): Promise<Uint8Array> {
    const digest = await subtle.digest('SHA-512', toBufferSource(data))
    return new Uint8Array(digest)
}

export async function hmacSha256Async(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await subtle.importKey('raw', toBufferSource(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const mac = await subtle.sign('HMAC', cryptoKey, toBufferSource(data))
    return new Uint8Array(mac)
}

export async function hkdfAsync(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    options: HKDFOptions
): Promise<Uint8Array> {
    const length = options.length
    if (!Number.isInteger(length) || length <= 0) throw new Error('length must be positive integer')
    if (ikm.length === 0) throw new Error('IKM cannot be empty')

    const maxLength = 255 * 32
    if (length > maxLength) throw new Error(`HKDF length must be <= ${maxLength}`)

    const sourceKey = await subtle.importKey('raw', toBufferSource(ikm), 'HKDF', false, ['deriveBits'])
    const bits = await subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: toBufferSource(salt),
            info: toBufferSource(info)
        },
        sourceKey,
        length * 8
    )

    return new Uint8Array(bits)
}

export const cryptoAsync = {
    encrypt: encryptAsync,
    decrypt: decryptAsync,
    hkdf: hkdfAsync,
    sha512: sha512Async,
    hmacSha256: hmacSha256Async
} as const

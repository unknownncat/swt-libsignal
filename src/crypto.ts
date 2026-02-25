import {
    createCipheriv,
    createDecipheriv,
    createHmac,
    createHash,
    randomBytes
} from 'node:crypto'
import { secureZero } from './utils/secure-zero'

const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_LENGTH = 32

function toBufferView(data: Uint8Array): Buffer {
    return Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

function wipe(buf: Buffer) {
    secureZero(buf)
}

function encrypt(
    key: Uint8Array,
    plaintext: Uint8Array,
    options?: { aad?: Uint8Array; iv?: Uint8Array }
): { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array } {
    // TODO(protocol-risk): default payload primitive is AES-256-GCM (education/proprietary wire mode).
    if (key.length !== KEY_LENGTH) {
        throw new Error('Key must be 32 bytes')
    }

    const iv = options?.iv ?? randomBytes(IV_LENGTH)
    if (iv.length !== IV_LENGTH) {
        throw new Error('IV must be 12 bytes for AES-GCM')
    }

    const k = Buffer.from(key)

    try {
        const cipher = createCipheriv('aes-256-gcm', k, toBufferView(iv))

        if (options?.aad) {
            cipher.setAAD(toBufferView(options.aad))
        }

        const ciphertext = Buffer.concat([
            cipher.update(toBufferView(plaintext)),
            cipher.final()
        ])

        const tag = cipher.getAuthTag()

        return {
            ciphertext: new Uint8Array(ciphertext.buffer, ciphertext.byteOffset, ciphertext.byteLength),
            iv: new Uint8Array(iv.buffer, iv.byteOffset, iv.byteLength),
            tag: new Uint8Array(tag.buffer, tag.byteOffset, tag.byteLength)
        }
    } finally {
        wipe(k)
    }
}

function decrypt(
    key: Uint8Array,
    data: { ciphertext: Uint8Array; iv: Uint8Array; tag: Uint8Array },
    options?: { aad?: Uint8Array }
): Uint8Array {
    // TODO(protocol-risk): decrypt expects GCM payload tuple {iv,ciphertext,tag}; SessionCipher adds outer HMAC separately.
    if (key.length !== KEY_LENGTH) {
        throw new Error('Key must be 32 bytes')
    }

    if (data.iv.length !== IV_LENGTH) {
        throw new Error('IV must be 12 bytes for AES-GCM')
    }
    if (data.tag.length !== TAG_LENGTH) {
        throw new Error('Tag must be 16 bytes for AES-GCM')
    }

    const k = Buffer.from(key)

    try {
        const decipher = createDecipheriv(
            'aes-256-gcm',
            k,
            toBufferView(data.iv)
        )

        if (options?.aad) {
            decipher.setAAD(toBufferView(options.aad))
        }

        decipher.setAuthTag(toBufferView(data.tag))

        const plaintext = Buffer.concat([
            decipher.update(toBufferView(data.ciphertext)),
            decipher.final()
        ])

        return new Uint8Array(
            plaintext.buffer,
            plaintext.byteOffset,
            plaintext.byteLength
        )
    } finally {
        wipe(k)
    }
}

function sha512(data: Uint8Array): Uint8Array {
    const out = createHash('sha512')
        .update(toBufferView(data))
        .digest()

    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength)
}

function hmacSha256(
    key: Uint8Array,
    data: Uint8Array
): Uint8Array {
    const out = createHmac('sha256', toBufferView(key))
        .update(toBufferView(data))
        .digest()

    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength)
}

function hkdf(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    options: { length: number }
): Uint8Array {
    const length = options.length
    if (!Number.isInteger(length) || length <= 0) {
        throw new Error('length must be positive integer')
    }
    if (ikm.length === 0) {
        throw new Error('IKM cannot be empty')
    }

    const hashLen = 32
    const maxLength = 255 * hashLen
    if (length > maxLength) {
        throw new Error(`HKDF length must be <= ${maxLength}`)
    }

    const prk = hmacSha256(salt, ikm)
    const okm = new Uint8Array(length)

    let t: Uint8Array = new Uint8Array(0)
    let offset = 0
    let counter = 1

    try {
        while (offset < length) {
            const input = new Uint8Array(t.length + info.length + 1)
            input.set(t, 0)
            input.set(info, t.length)
            input[input.length - 1] = counter

            const nextT = hmacSha256(prk, input)
            secureZero(input)
            secureZero(t)
            t = nextT

            const chunkLength = Math.min(hashLen, length - offset)
            okm.set(t.subarray(0, chunkLength), offset)
            offset += chunkLength
            counter += 1
        }

        return okm
    } finally {
        secureZero(prk)
        secureZero(t)
    }
}

export const crypto = {
    encrypt,
    decrypt,
    hkdf,
    sha512,
    hmacSha256
} as const

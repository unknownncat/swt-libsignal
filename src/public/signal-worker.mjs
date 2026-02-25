import libsodium from 'libsodium-wrappers'
import { createCipheriv, createDecipheriv, createHmac, createHash, randomBytes } from 'node:crypto'
import { isMainThread, parentPort, threadId } from 'node:worker_threads'

const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_LENGTH = 32

const toBufferView = (data) => Buffer.isBuffer(data)
    ? data
    : Buffer.from(data.buffer, data.byteOffset, data.byteLength)

function encrypt(key, plaintext, options) {
    if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes')
    const iv = options?.iv ?? randomBytes(IV_LENGTH)
    if (iv.length !== IV_LENGTH) throw new Error('IV must be 12 bytes for AES-GCM')
    const k = toBufferView(key)
    const cipher = createCipheriv('aes-256-gcm', k, toBufferView(iv))
    if (options?.aad) cipher.setAAD(toBufferView(options.aad))
    const ciphertext = Buffer.concat([cipher.update(toBufferView(plaintext)), cipher.final()])
    const tag = cipher.getAuthTag()
    return { ciphertext: new Uint8Array(ciphertext), iv: new Uint8Array(iv), tag: new Uint8Array(tag) }
}

function decrypt(key, data, options) {
    if (key.length !== KEY_LENGTH) throw new Error('Key must be 32 bytes')
    if (data.iv.length !== IV_LENGTH) throw new Error('IV must be 12 bytes for AES-GCM')
    if (data.tag.length !== TAG_LENGTH) throw new Error('Tag must be 16 bytes for AES-GCM')
    const k = toBufferView(key)
    const decipher = createDecipheriv('aes-256-gcm', k, toBufferView(data.iv))
    if (options?.aad) decipher.setAAD(toBufferView(options.aad))
    decipher.setAuthTag(toBufferView(data.tag))
    const plaintext = Buffer.concat([decipher.update(toBufferView(data.ciphertext)), decipher.final()])
    return new Uint8Array(plaintext)
}

const sha512 = (data) => new Uint8Array(createHash('sha512').update(toBufferView(data)).digest())
const hmacSha256 = (key, data) => new Uint8Array(createHmac('sha256', toBufferView(key)).update(toBufferView(data)).digest())

function hkdf(ikm, salt, info, options) {
    const length = options.length
    if (!Number.isInteger(length) || length <= 0) throw new Error('length must be positive integer')
    if (ikm.length === 0) throw new Error('IKM cannot be empty')
    const hashLen = 32
    const maxLength = 255 * hashLen
    if (length > maxLength) throw new Error(`HKDF length must be <= ${maxLength}`)

    const prk = hmacSha256(salt, ikm)
    const okm = new Uint8Array(length)
    let t = new Uint8Array(0)
    let offset = 0
    let counter = 1
    try {
        while (offset < length) {
            const input = new Uint8Array(t.length + info.length + 1)
            input.set(t, 0)
            input.set(info, t.length)
            input[input.length - 1] = counter
            const nextT = hmacSha256(prk, input)
            input.fill(0)
            t.fill(0)
            t = nextT
            const chunkLength = Math.min(hashLen, length - offset)
            okm.set(t.subarray(0, chunkLength), offset)
            offset += chunkLength
            counter += 1
        }
        return okm
    } finally {
        prk.fill(0)
        t.fill(0)
    }
}

function run(req) {
    switch (req.type) {
        case 'encrypt': return encrypt(req.payload.key, req.payload.plaintext, req.payload.options)
        case 'decrypt': return decrypt(req.payload.key, req.payload.data, req.payload.options)
        case 'sha512': return sha512(req.payload.data)
        case 'hmacSha256': return hmacSha256(req.payload.key, req.payload.data)
        case 'hkdf': return hkdf(req.payload.ikm, req.payload.salt, req.payload.info, req.payload.options)
        case 'threadInfo': return { threadId, isMainThread }
        default: throw new Error('unsupported request type')
    }
}

const transferListForValue = (value) => {
    if (value instanceof Uint8Array) return [value.buffer]
    if (value && typeof value === 'object' && 'ciphertext' in value) {
        return [value.ciphertext.buffer, value.iv.buffer, value.tag.buffer]
    }
    return []
}

await libsodium.ready

parentPort?.on('message', (envelope) => {
    const { id, request } = envelope
    try {
        const value = run(request)
        parentPort?.postMessage({ id, response: { ok: true, type: request.type, value } }, transferListForValue(value))
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        parentPort?.postMessage({ id, response: { ok: false, message } })
    }
})

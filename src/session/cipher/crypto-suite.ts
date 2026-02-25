import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto'
import { crypto } from '../../crypto'
import type { WhisperMessageProto } from './types'

const GCM_IV_LENGTH = 12
const GCM_TAG_LENGTH = 16
const CBC_IV_LENGTH = 16
const HMAC_SHA256_LENGTH = 32

export interface MessageMetadata {
    ephemeralKey: Uint8Array
    counter: number
    previousCounter: number
}

export interface AssociatedDataContext {
    senderIdentityKey: Uint8Array
    receiverIdentityKey: Uint8Array
    versionByte: number
    message: MessageMetadata
    aadKey: Uint8Array
}

export interface EncryptPayloadContext {
    cipherKey: Uint8Array
    macKey: Uint8Array
    plaintext: Uint8Array
    associatedData: Uint8Array
    iv?: Uint8Array
}

export interface DecryptPayloadContext {
    cipherKey: Uint8Array
    macKey: Uint8Array
    payload: Uint8Array
    associatedData: Uint8Array
}

export interface CryptoSuite {
    readonly name: string
    buildAssociatedData(context: AssociatedDataContext): Uint8Array
    encryptPayload(context: EncryptPayloadContext): Uint8Array
    decryptPayload(context: DecryptPayloadContext): Uint8Array
    mac(key: Uint8Array, data: Uint8Array, length: number): Uint8Array
    verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array, length: number): void
}

function toBufferView(data: Uint8Array): Buffer {
    return Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
    let length = 0
    for (let i = 0; i < parts.length; i++) {
        length += parts[i]!.length
    }

    const out = new Uint8Array(length)
    let offset = 0
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i]!
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function encodeCounterPair(counter: number, previousCounter: number): Uint8Array {
    const out = new Uint8Array(8)
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
    view.setUint32(0, counter, false)
    view.setUint32(4, previousCounter, false)
    return out
}

function assertMacLength(mac: Uint8Array, length: number): void {
    if (mac.length < length) {
        throw new Error('MAC too short')
    }
}

function computeMac(key: Uint8Array, data: Uint8Array, length: number): Uint8Array {
    const full = crypto.hmacSha256(key, data)
    return full.subarray(0, length)
}

function verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array, length: number): void {
    assertMacLength(mac, length)
    const expected = Buffer.from(computeMac(key, data, length))
    const actual = Buffer.from(mac.subarray(0, length))
    if (!timingSafeEqual(expected, actual)) {
        throw new Error('MAC verification failed')
    }
}

function gcmEncrypt(context: EncryptPayloadContext): Uint8Array {
    const encrypted = context.iv
        ? crypto.encrypt(context.cipherKey, context.plaintext, {
            aad: context.associatedData,
            iv: context.iv
        })
        : crypto.encrypt(context.cipherKey, context.plaintext, {
            aad: context.associatedData
        })
    return concatBytes([encrypted.iv, encrypted.ciphertext, encrypted.tag])
}

function gcmDecrypt(context: DecryptPayloadContext): Uint8Array {
    if (context.payload.length < GCM_IV_LENGTH + GCM_TAG_LENGTH) {
        throw new Error('Invalid ciphertext payload')
    }

    const iv = context.payload.subarray(0, GCM_IV_LENGTH)
    const tag = context.payload.subarray(context.payload.length - GCM_TAG_LENGTH)
    const ciphertext = context.payload.subarray(GCM_IV_LENGTH, context.payload.length - GCM_TAG_LENGTH)
    return crypto.decrypt(context.cipherKey, { ciphertext, iv, tag }, { aad: context.associatedData })
}

function cbcHmacEncrypt(context: EncryptPayloadContext): Uint8Array {
    const iv = context.iv ?? randomBytes(CBC_IV_LENGTH)
    if (iv.length !== CBC_IV_LENGTH) {
        throw new Error('IV must be 16 bytes for AES-CBC')
    }

    const cipher = createCipheriv('aes-256-cbc', toBufferView(context.cipherKey), toBufferView(iv))
    const ciphertext = Buffer.concat([
        cipher.update(toBufferView(context.plaintext)),
        cipher.final()
    ])

    const ciphertextView = new Uint8Array(ciphertext.buffer, ciphertext.byteOffset, ciphertext.byteLength)
    const macInput = concatBytes([context.associatedData, iv, ciphertextView])
    const mac = computeMac(context.macKey, macInput, HMAC_SHA256_LENGTH)
    return concatBytes([iv, ciphertextView, mac])
}

function cbcHmacDecrypt(context: DecryptPayloadContext): Uint8Array {
    if (context.payload.length < CBC_IV_LENGTH + HMAC_SHA256_LENGTH + 16) {
        throw new Error('Invalid ciphertext payload')
    }

    const iv = context.payload.subarray(0, CBC_IV_LENGTH)
    const mac = context.payload.subarray(context.payload.length - HMAC_SHA256_LENGTH)
    const ciphertext = context.payload.subarray(CBC_IV_LENGTH, context.payload.length - HMAC_SHA256_LENGTH)

    if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
        throw new Error('Invalid ciphertext payload')
    }

    const macInput = concatBytes([context.associatedData, iv, ciphertext])
    verifyMac(context.macKey, macInput, mac, HMAC_SHA256_LENGTH)

    const decipher = createDecipheriv('aes-256-cbc', toBufferView(context.cipherKey), toBufferView(iv))
    const plaintext = Buffer.concat([
        decipher.update(toBufferView(ciphertext)),
        decipher.final()
    ])

    return new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength)
}

export const GcmSuite: CryptoSuite = {
    name: 'gcm',
    buildAssociatedData(context: AssociatedDataContext): Uint8Array {
        // Educational/default mode keeps historical behavior: aadKey prefix as payload AAD.
        return context.aadKey.subarray(0, 16)
    },
    encryptPayload(context: EncryptPayloadContext): Uint8Array {
        return gcmEncrypt(context)
    },
    decryptPayload(context: DecryptPayloadContext): Uint8Array {
        return gcmDecrypt(context)
    },
    mac(key: Uint8Array, data: Uint8Array, length: number): Uint8Array {
        return computeMac(key, data, length)
    },
    verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array, length: number): void {
        verifyMac(key, data, mac, length)
    }
}

export const CbcHmacSuite: CryptoSuite = {
    name: 'cbc-hmac',
    buildAssociatedData(context: AssociatedDataContext): Uint8Array {
        const counters = encodeCounterPair(context.message.counter, context.message.previousCounter)
        return concatBytes([
            context.senderIdentityKey,
            context.receiverIdentityKey,
            Uint8Array.of(context.versionByte),
            context.message.ephemeralKey,
            counters
        ])
    },
    encryptPayload(context: EncryptPayloadContext): Uint8Array {
        return cbcHmacEncrypt(context)
    },
    decryptPayload(context: DecryptPayloadContext): Uint8Array {
        return cbcHmacDecrypt(context)
    },
    mac(key: Uint8Array, data: Uint8Array, length: number): Uint8Array {
        return computeMac(key, data, length)
    },
    verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array, length: number): void {
        verifyMac(key, data, mac, length)
    }
}

export function buildTransportMacInput(
    senderIdentityKey: Uint8Array,
    receiverIdentityKey: Uint8Array,
    versionByte: number,
    messageProto: Uint8Array
): Uint8Array {
    const macInput = new Uint8Array(messageProto.byteLength + 67)
    macInput.set(senderIdentityKey)
    macInput.set(receiverIdentityKey, 33)
    macInput[66] = versionByte
    macInput.set(messageProto, 67)
    return macInput
}

export function buildDecryptTransportMacInput(
    senderIdentityKey: Uint8Array,
    receiverIdentityKey: Uint8Array,
    versionByte: number,
    messageBuffer: Uint8Array
): { macInput: Uint8Array; messageProto: Uint8Array; messageEnd: number } {
    const messageEnd = messageBuffer.byteLength - 8
    const messageProto = messageBuffer.subarray(1, messageEnd)
    const macInput = new Uint8Array(messageEnd + 67)
    macInput.set(senderIdentityKey)
    macInput.set(receiverIdentityKey, 33)
    macInput[66] = versionByte
    macInput.set(messageProto, 67)
    return { macInput, messageProto, messageEnd }
}

export function buildMessageMetadata(message: WhisperMessageProto): MessageMetadata {
    return {
        ephemeralKey: message.ephemeralKey,
        counter: message.counter,
        previousCounter: message.previousCounter
    }
}

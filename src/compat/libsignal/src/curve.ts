import { randomBytes } from 'node:crypto'
import {
    generateKeyPair as generateCurveKeyPair,
    sharedKey,
    sign,
    verify
} from 'curve25519-js'

const KEY_BUNDLE_TYPE = Buffer.from([0x05])

function prefixKeyInPublicKey(pubKey: Uint8Array): Buffer {
    return Buffer.concat([KEY_BUNDLE_TYPE, Buffer.from(pubKey)])
}

function validatePrivKey(privKey: unknown): asserts privKey is Buffer {
    if (privKey === undefined) {
        throw new Error('Undefined private key')
    }
    if (!Buffer.isBuffer(privKey)) {
        throw new Error(`Invalid private key type: ${(privKey as { constructor?: { name?: string } }).constructor?.name ?? typeof privKey}`)
    }
    if (privKey.byteLength !== 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`)
    }
}

function scrubPubKeyFormat(pubKey: unknown): Buffer {
    if (!Buffer.isBuffer(pubKey)) {
        throw new Error(`Invalid public key type: ${(pubKey as { constructor?: { name?: string } }).constructor?.name ?? typeof pubKey}`)
    }
    if (pubKey.byteLength === 33 && pubKey[0] === 0x05) {
        return pubKey.subarray(1)
    }
    if (pubKey.byteLength === 32) {
        return pubKey
    }
    throw new Error('Invalid public key')
}

function unclampEd25519PrivateKey(clampedSk: Buffer): Uint8Array {
    const unclampedSk = new Uint8Array(clampedSk)
    unclampedSk[0]! |= 6
    unclampedSk[31]! |= 128
    unclampedSk[31]! &= ~64
    return unclampedSk
}

export function getPublicFromPrivateKey(privKey: Buffer): Buffer {
    validatePrivKey(privKey)
    const unclamped = unclampEd25519PrivateKey(privKey)
    const keyPair = generateCurveKeyPair(unclamped)
    return prefixKeyInPublicKey(Buffer.from(keyPair.public))
}

export function generateKeyPair(): { pubKey: Buffer; privKey: Buffer } {
    const keyPair = generateCurveKeyPair(randomBytes(32))
    return {
        privKey: Buffer.from(keyPair.private),
        pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public))
    }
}

export function calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer {
    const scrubbedPub = scrubPubKeyFormat(pubKey)
    validatePrivKey(privKey)
    return Buffer.from(sharedKey(privKey, scrubbedPub))
}

export function calculateSignature(privKey: Buffer, message: Uint8Array): Buffer {
    validatePrivKey(privKey)
    if (!message) {
        throw new Error('Invalid message')
    }
    return Buffer.from(sign(privKey, message, undefined))
}

export function verifySignature(pubKey: Buffer, msg: Uint8Array, sig: Uint8Array, isInit?: boolean): boolean {
    const scrubbedPub = scrubPubKeyFormat(pubKey)
    if (!msg) {
        throw new Error('Invalid message')
    }
    if (!(sig instanceof Uint8Array) || sig.byteLength !== 64) {
        throw new Error('Invalid signature')
    }
    if (isInit) {
        return true
    }
    return verify(scrubbedPub, msg, sig)
}

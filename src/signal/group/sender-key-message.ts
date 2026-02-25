import { sign, verify } from 'curve25519-js'
import { CiphertextMessage } from './ciphertext-message'
import { SenderKeyMessageCodec } from './proto'

function scrubSenderPublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length === 33 && publicKey[0] === 0x05) {
        return publicKey.subarray(1)
    }
    if (publicKey.length === 32) {
        return publicKey
    }
    throw new Error('Invalid sender signing public key')
}

export class SenderKeyMessage extends CiphertextMessage {
    private readonly SIGNATURE_LENGTH = 64
    private readonly messageVersion: number
    private readonly keyId: number
    private readonly iteration: number
    private readonly ciphertext: Uint8Array
    private readonly signature: Uint8Array
    private readonly serialized: Uint8Array

    constructor(
        keyId?: number,
        iteration?: number,
        ciphertext?: Uint8Array,
        signatureKey?: Uint8Array,
        serialized?: Uint8Array
    ) {
        super()

        if (serialized) {
            if (serialized.length <= 1 + this.SIGNATURE_LENGTH) {
                throw new Error('Invalid SenderKeyMessage payload')
            }
            const version = serialized[0]!
            const message = serialized.subarray(1, serialized.length - this.SIGNATURE_LENGTH)
            const signature = serialized.subarray(serialized.length - this.SIGNATURE_LENGTH)
            const decoded = SenderKeyMessageCodec.decode(message)

            if (typeof decoded.id !== 'number' || typeof decoded.iteration !== 'number' || !(decoded.ciphertext instanceof Uint8Array)) {
                throw new Error('Invalid SenderKeyMessage payload')
            }

            this.serialized = serialized
            this.messageVersion = version >> 4
            this.keyId = decoded.id
            this.iteration = decoded.iteration
            this.ciphertext = decoded.ciphertext
            this.signature = signature
            return
        }

        if (typeof keyId !== 'number' || typeof iteration !== 'number' || !(ciphertext instanceof Uint8Array) || !(signatureKey instanceof Uint8Array)) {
            throw new Error('Invalid SenderKeyMessage constructor arguments')
        }

        const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
        const message = SenderKeyMessageCodec.encode({
            id: keyId,
            iteration,
            ciphertext
        })
        const body = new Uint8Array(1 + message.length)
        body[0] = version
        body.set(message, 1)

        const signature = sign(signatureKey, body, undefined)
        const packed = new Uint8Array(body.length + signature.length)
        packed.set(body, 0)
        packed.set(signature, body.length)

        this.serialized = packed
        this.messageVersion = this.CURRENT_VERSION
        this.keyId = keyId
        this.iteration = iteration
        this.ciphertext = ciphertext
        this.signature = signature
    }

    getKeyId(): number {
        return this.keyId
    }

    getIteration(): number {
        return this.iteration
    }

    getCipherText(): Uint8Array {
        return this.ciphertext
    }

    verifySignature(signatureKey: Uint8Array): void {
        const payload = this.serialized.subarray(0, this.serialized.length - this.SIGNATURE_LENGTH)
        const valid = verify(scrubSenderPublicKey(signatureKey), payload, this.signature)
        if (!valid) throw new Error('Invalid signature')
    }

    serialize(): Uint8Array {
        return this.serialized
    }

    getType(): number {
        return this.SENDERKEY_TYPE
    }
}

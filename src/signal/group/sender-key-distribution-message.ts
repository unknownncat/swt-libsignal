import { CiphertextMessage } from './ciphertext-message'
import { SenderKeyDistributionMessageCodec } from './proto'

export class SenderKeyDistributionMessage extends CiphertextMessage {
    private readonly id: number
    private readonly iteration: number
    private readonly chainKey: Uint8Array
    private readonly signatureKey: Uint8Array
    private readonly serialized: Uint8Array

    constructor(
        id?: number,
        iteration?: number,
        chainKey?: Uint8Array,
        signatureKey?: Uint8Array,
        serialized?: Uint8Array
    ) {
        super()

        if (serialized) {
            if (serialized.length < 2) {
                throw new Error('Invalid SenderKeyDistributionMessage payload')
            }
            const message = serialized.subarray(1)
            const decoded = SenderKeyDistributionMessageCodec.decode(message)
            if (
                typeof decoded.id !== 'number' ||
                typeof decoded.iteration !== 'number' ||
                !(decoded.chainKey instanceof Uint8Array) ||
                !(decoded.signingKey instanceof Uint8Array)
            ) {
                throw new Error('Invalid SenderKeyDistributionMessage payload')
            }

            this.serialized = serialized
            this.id = decoded.id
            this.iteration = decoded.iteration
            this.chainKey = decoded.chainKey
            this.signatureKey = decoded.signingKey
            return
        }

        if (
            typeof id !== 'number' ||
            typeof iteration !== 'number' ||
            !(chainKey instanceof Uint8Array) ||
            !(signatureKey instanceof Uint8Array)
        ) {
            throw new Error('Invalid SenderKeyDistributionMessage constructor arguments')
        }

        const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
        const message = SenderKeyDistributionMessageCodec.encode({
            id,
            iteration,
            chainKey,
            signingKey: signatureKey
        })
        const out = new Uint8Array(1 + message.length)
        out[0] = version
        out.set(message, 1)

        this.serialized = out
        this.id = id
        this.iteration = iteration
        this.chainKey = chainKey
        this.signatureKey = signatureKey
    }

    serialize(): Uint8Array {
        return this.serialized
    }

    getType(): number {
        return this.SENDERKEY_DISTRIBUTION_TYPE
    }

    getIteration(): number {
        return this.iteration
    }

    getChainKey(): Uint8Array {
        return this.chainKey
    }

    getSignatureKey(): Uint8Array {
        return this.signatureKey
    }

    getId(): number {
        return this.id
    }
}

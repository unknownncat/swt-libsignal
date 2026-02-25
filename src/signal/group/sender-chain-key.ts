import { crypto } from '../../crypto'
import { SenderMessageKey } from './sender-message-key'

const MESSAGE_KEY_SEED = Uint8Array.of(0x01)
const CHAIN_KEY_SEED = Uint8Array.of(0x02)

export class SenderChainKey {
    private readonly iteration: number
    private readonly chainKey: Uint8Array

    constructor(iteration: number, chainKey: Uint8Array) {
        this.iteration = iteration
        this.chainKey = chainKey
    }

    getIteration(): number {
        return this.iteration
    }

    getSenderMessageKey(): SenderMessageKey {
        return new SenderMessageKey(this.iteration, this.getDerivative(MESSAGE_KEY_SEED))
    }

    getNext(): SenderChainKey {
        return new SenderChainKey(this.iteration + 1, this.getDerivative(CHAIN_KEY_SEED))
    }

    getSeed(): Uint8Array {
        return this.chainKey
    }

    private getDerivative(seed: Uint8Array): Uint8Array {
        return crypto.hmacSha256(this.chainKey, seed)
    }
}

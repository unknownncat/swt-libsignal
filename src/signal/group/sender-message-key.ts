import { crypto } from '../../crypto'
import { TEXT_ENCODER, zero32 } from '../../internal/constants/crypto'

const HKDF_INFO_WHISPER_GROUP = TEXT_ENCODER.encode('WhisperGroup')

export class SenderMessageKey {
    private readonly iteration: number
    private readonly iv: Uint8Array
    private readonly cipherKey: Uint8Array
    private readonly seed: Uint8Array

    constructor(iteration: number, seed: Uint8Array) {
        const derived = crypto.hkdf(seed, zero32(), HKDF_INFO_WHISPER_GROUP, { length: 64 })
        this.iv = derived.subarray(0, 16)
        this.cipherKey = derived.subarray(16, 48)
        this.iteration = iteration
        this.seed = seed
    }

    getIteration(): number {
        return this.iteration
    }

    getIv(): Uint8Array {
        return this.iv
    }

    getCipherKey(): Uint8Array {
        return this.cipherKey
    }

    getSeed(): Uint8Array {
        return this.seed
    }
}

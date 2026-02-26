import { WhisperMessageEncoder } from '../../../session/cipher/encoding'
import type { PreKeyWhisperMessageProto, WhisperMessageProto } from '../../../session/cipher/types'

function toUint8(value: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function asFinishable(bytes: Uint8Array): { finish(): Uint8Array } {
    return {
        finish: () => bytes
    }
}

export const WhisperMessage = {
    encode(message: WhisperMessageProto): { finish(): Uint8Array } {
        return asFinishable(WhisperMessageEncoder.encodeWhisperMessage(message))
    },
    decode(payload: Uint8Array | Buffer): WhisperMessageProto {
        return WhisperMessageEncoder.decodeWhisperMessage(toUint8(payload))
    }
}

export const PreKeyWhisperMessage = {
    encode(message: PreKeyWhisperMessageProto): { finish(): Uint8Array } {
        return asFinishable(WhisperMessageEncoder.encodePreKeyWhisperMessage(message))
    },
    decode(payload: Uint8Array | Buffer): PreKeyWhisperMessageProto {
        return WhisperMessageEncoder.decodePreKeyWhisperMessage(toUint8(payload))
    }
}

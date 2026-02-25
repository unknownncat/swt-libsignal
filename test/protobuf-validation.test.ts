import { describe, expect, it } from 'vitest'
import { WhisperMessageEncoder } from '../src/session/cipher/encoding'

describe('protobuf input validation hardening', () => {
    it('rejects malformed varints and oversized payloads', () => {
        expect(() => WhisperMessageEncoder.decodeWhisperMessage(new Uint8Array([0x80]))).toThrow('Malformed varint')
        const huge = new Uint8Array(512 * 1024 + 1)
        expect(() => WhisperMessageEncoder.decodePreKeyWhisperMessage(huge)).toThrow('payload size is invalid')
    })
})

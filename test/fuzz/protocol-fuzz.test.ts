import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import { crypto } from '../../src/crypto'
import { WhisperMessageEncoder } from '../../src/session/cipher/encoding'
import * as compatCrypto from '../../src/compat/libsignal/src/crypto'

const runFuzz = process.env.RUN_FUZZ === '1'
const runs = Number(process.env.FC_NUM_RUNS ?? '500')
const describeFuzz = runFuzz ? describe : describe.skip

describeFuzz('protocol fuzz harness', () => {
  it('keeps AES-GCM encrypt/decrypt roundtrip stable for random payloads', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 0, maxLength: 8192 }),
        fc.uint8Array({ minLength: 12, maxLength: 12 }),
        fc.uint8Array({ minLength: 0, maxLength: 64 }),
        (key, payload, iv, aad) => {
          const encrypted = crypto.encrypt(key, payload, { iv, aad })
          const decrypted = crypto.decrypt(key, encrypted, { aad })
          expect(decrypted).toEqual(payload)
        }
      ),
      { numRuns: runs }
    )
  })

  it('keeps WhisperMessage codec roundtrip stable for random valid payloads', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 33 }),
        fc.nat({ max: 100_000 }),
        fc.nat({ max: 100_000 }),
        fc.uint8Array({ minLength: 1, maxLength: 16_384 }),
        (ephemeralKey, counter, previousCounter, ciphertext) => {
          const encoded = WhisperMessageEncoder.encodeWhisperMessage({
            ephemeralKey,
            counter,
            previousCounter,
            ciphertext,
          })
          const decoded = WhisperMessageEncoder.decodeWhisperMessage(encoded)
          expect(decoded.ephemeralKey).toEqual(ephemeralKey)
          expect(decoded.counter).toBe(counter)
          expect(decoded.previousCounter).toBe(previousCounter)
          expect(decoded.ciphertext).toEqual(ciphertext)
        }
      ),
      { numRuns: Math.max(200, Math.floor(runs / 2)) }
    )
  })

  it('never crashes on arbitrary malformed protobuf payloads', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 2048 }),
        (bytes) => {
          try {
            WhisperMessageEncoder.decodeWhisperMessage(bytes)
          } catch (error) {
            expect(error).toBeInstanceOf(Error)
          }
        }
      ),
      { numRuns: Math.max(200, Math.floor(runs / 2)) }
    )
  })

  it('keeps compat deriveSecrets output aligned with the original libsignal implementation', async () => {
    // @ts-expect-error upstream package has no TS declarations for subpath imports
    const legacyCrypto = await import('libsignal/src/crypto')

    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        (input, salt, info) => {
          const ours = compatCrypto.deriveSecrets(Buffer.from(input), Buffer.from(salt), Buffer.from(info))
          const theirs = legacyCrypto.deriveSecrets(Buffer.from(input), Buffer.from(salt), Buffer.from(info))
          expect(ours).toHaveLength(3)
          expect(theirs).toHaveLength(3)
          expect(Buffer.compare(Buffer.from(ours[0]!), Buffer.from(theirs[0]!))).toBe(0)
          expect(Buffer.compare(Buffer.from(ours[1]!), Buffer.from(theirs[1]!))).toBe(0)
          expect(Buffer.compare(Buffer.from(ours[2]!), Buffer.from(theirs[2]!))).toBe(0)
        }
      ),
      { numRuns: Math.max(200, Math.floor(runs / 2)) }
    )
  })
})


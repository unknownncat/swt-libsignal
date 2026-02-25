import { describe, expect, it } from 'vitest'
import { signalCrypto } from '../../src/curve'
import { asEd25519PublicKey, asEd25519SecretKey, asX25519PublicKey } from '../../src/types/branded'

describe('curve key format guards', () => {
    it('fails fast on invalid key sizes and supports explicit Ed25519->X25519 conversion', async () => {
        const identity = await signalCrypto.generateIdentityKeyPair()
        const converted = signalCrypto.convertIdentityPublicToX25519(asEd25519PublicKey(identity.publicKey))
        expect(asX25519PublicKey(converted)).toBeDefined()

        expect(() => asEd25519PublicKey(new Uint8Array(31))).toThrow('Ed25519 public key must be 32 bytes')
        expect(() => asEd25519SecretKey(new Uint8Array(32))).toThrow('Ed25519 private key must be 64 bytes')
        expect(() => signalCrypto.calculateAgreement(new Uint8Array(31), new Uint8Array(32))).toThrow('X25519 public key must be 32 bytes')
    })
})

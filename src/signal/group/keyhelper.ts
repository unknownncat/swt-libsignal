import { randomBytes, randomInt } from 'node:crypto'
import { generateKeyPair } from 'curve25519-js'

export interface SigningKeyPair {
    readonly public: Uint8Array
    readonly private: Uint8Array
}

export function generateSenderKey(): Uint8Array {
    return randomBytes(32)
}

export function generateSenderKeyId(): number {
    return randomInt(0x7fffffff)
}

export async function generateSenderSigningKey(): Promise<SigningKeyPair> {
    const keyPair = generateKeyPair(randomBytes(32))
    const publicKey = new Uint8Array(33)
    publicKey[0] = 0x05
    publicKey.set(keyPair.public, 1)

    return {
        public: publicKey,
        private: keyPair.private
    }
}

import type { PreKeyBundle } from '../session/builder'
import type { ProtocolAddress } from '../protocol_address'

import { SessionBuilder } from '../session/builder/session-builder'
import { SessionCipher } from '../session/cipher/session-cipher'
import { cryptoAsync } from '../crypto-async'
import {
    generateIdentityKeyPairAsync,
    generatePreKeyAsync,
    generateRegistrationIdAsync,
    generateSignedPreKeyAsync
} from '../key-helper-async'

export { cryptoAsync }
export {
    generateIdentityKeyPairAsync,
    generatePreKeyAsync,
    generateRegistrationIdAsync,
    generateSignedPreKeyAsync
}

// Funções utilitárias para uma API funcional assíncrona explícita.
export async function establishSessionAsync(
    storage: ConstructorParameters<typeof SessionBuilder>[0],
    protocolAddress: ProtocolAddress,
    device: PreKeyBundle
): Promise<void> {
    const builder = new SessionBuilder(storage, protocolAddress)
    await builder.initOutgoing(device)
}

export async function encryptAsync(cipher: SessionCipher, message: Uint8Array) {
    return cipher.encrypt(message)
}

export async function decryptAsync(cipher: SessionCipher, message: Uint8Array) {
    return cipher.decryptWhisperMessage(message)
}

import { randomBytes } from 'node:crypto'

import type { IdentityKeyPair } from './types/asymmetric'
import type { PreKey, SignedPreKey } from './key-helper'
import {
    generateIdentityKeyPair,
    generatePreKey,
    generateSignedPreKey
} from './key-helper'

// API assíncrona dedicada para manter compatibilidade com chamadas síncronas existentes.
export const generateIdentityKeyPairAsync = generateIdentityKeyPair
export const generateSignedPreKeyAsync = generateSignedPreKey
export const generatePreKeyAsync = generatePreKey

export async function generateRegistrationIdAsync(): Promise<number> {
    const bytes = await new Promise<Buffer>((resolve, reject) => {
        randomBytes(2, (error, buffer) => {
            if (error) {
                reject(error)
                return
            }
            resolve(buffer)
        })
    })

    return (((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) & 0x3fff
}

export type { IdentityKeyPair, SignedPreKey, PreKey }

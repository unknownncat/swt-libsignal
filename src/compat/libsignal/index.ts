import { ProtocolAddress } from '../../protocol_address'
import { SessionBuilder as CoreSessionBuilder } from '../../session/builder/session-builder'
import { SessionCipher as CoreSessionCipher } from '../../session/cipher/session-cipher'
import { LegacyLibsignalSuite } from '../../session/cipher/crypto-suite'
import { SessionRecord } from '../../session/record/session-record'
import {
    MessageCounterError,
    PreKeyError,
    SessionError,
    SignalError,
    UntrustedIdentityKeyError
} from '../../signal-errors'

import type { E2ESession, SignalStorage } from './types'
import * as crypto from './src/crypto'
import * as curve from './src/curve'
import * as keyhelper from './src/keyhelper'

export class SessionBuilder {
    private readonly inner: CoreSessionBuilder

    constructor(storage: SignalStorage, remoteAddress: ProtocolAddress) {
        this.inner = new CoreSessionBuilder(storage, remoteAddress, { compatMode: 'legacy' })
    }

    async initOutgoing(session: E2ESession): Promise<void> {
        await this.inner.initOutgoing(session)
    }
}

export class SessionCipher {
    private readonly inner: CoreSessionCipher

    constructor(storage: SignalStorage, remoteAddress: ProtocolAddress) {
        this.inner = new CoreSessionCipher(storage, remoteAddress, {
            compatMode: 'legacy',
            cryptoSuite: LegacyLibsignalSuite
        })
    }

    async decryptPreKeyWhisperMessage(ciphertext: Uint8Array): Promise<Buffer> {
        const plaintext = await this.inner.decryptPreKeyWhisperMessage(ciphertext)
        return Buffer.from(plaintext)
    }

    async decryptWhisperMessage(ciphertext: Uint8Array): Promise<Buffer> {
        const plaintext = await this.inner.decryptWhisperMessage(ciphertext)
        return Buffer.from(plaintext)
    }

    async encrypt(data: Uint8Array): Promise<{ type: number; body: string }> {
        const encrypted = await this.inner.encrypt(data)
        return {
            type: encrypted.type,
            body: Buffer.from(encrypted.body).toString('binary')
        }
    }
}

export {
    crypto,
    curve,
    keyhelper,
    ProtocolAddress,
    SessionRecord,
    MessageCounterError,
    PreKeyError,
    SessionError,
    SignalError,
    UntrustedIdentityKeyError
}

export type { E2ESession, SignalStorage }

import { BaseKeyType, ChainType } from "../../ratchet-types"
import type { ProtocolAddress } from '../../protocol_address'
import { SessionRecord, SessionEntry, type PendingPreKey } from '../record/index'
import { crypto } from '../../crypto'
import { signalCrypto } from '../../curve'
import { UntrustedIdentityKeyError, PreKeyError } from '../../signal-errors'
import { enqueue } from '../../job_queue'
import { getSignalLogger } from '../../internal/logger'
import { verifySignature as verifyCurveSignature } from '../../compat/libsignal/src/curve'
import { generateKeyPair as generateLegacyCurveKeyPair } from '../../compat/libsignal/src/curve'

import type {
    PreKeyBundle,
    PreKeyWhisperMessage,
    SessionBuilderStorage,
    KeyPair,
    SessionBuilderOptions,
    CompatMode
} from './types'

import { HKDF_INFO_WHISPER_TEXT, TEXT_ENCODER, zero32 } from '../../internal/constants/crypto'

const HKDF_INFO_RATCHET = TEXT_ENCODER.encode('WhisperRatchet')

function toBufferView(data: Uint8Array): Buffer {
    return Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

export class SessionBuilder {
    private readonly addr: ProtocolAddress
    private readonly storage: SessionBuilderStorage
    private readonly compatMode: CompatMode
    private readonly warnCompat: (message: string) => void
    private legacyWarningEmitted = false

    private assertNotAborted(signal: AbortSignal): void {
        if (signal.aborted) {
            const reason = signal.reason
            throw reason instanceof Error ? reason : new Error('Operation aborted')
        }
    }

    constructor(storage: SessionBuilderStorage, protocolAddress: ProtocolAddress, options: SessionBuilderOptions = {}) {
        this.addr = protocolAddress
        this.storage = storage
        this.compatMode = options.compatMode ?? 'strict'
        this.warnCompat = options.warn ?? ((message: string) => { console.warn(message) })
    }

    async initOutgoing(device: PreKeyBundle): Promise<void> {
        //  - Validar device antes de processar
        if (!device) {
            throw new TypeError('device must be a PreKeyBundle')
        }

        if (!device.identityKey || device.identityKey.length === 0) {
            throw new Error('Invalid device.identityKey')
        }
        if (!device.signedPreKey) {
            throw new Error('Missing device.signedPreKey')
        }
        if (!device.signedPreKey.publicKey || device.signedPreKey.publicKey.length === 0) {
            throw new Error('Invalid device.signedPreKey.publicKey')
        }
        if (!device.signedPreKey.signature || device.signedPreKey.signature.length === 0) {
            throw new Error('Invalid device.signedPreKey.signature')
        }
        if (device.registrationId == null || device.registrationId < 0) {
            throw new Error('Invalid device.registrationId')
        }

        const fqAddr = this.addr.toString()

        return enqueue(fqAddr, async (signal) => {
            if (!await this.storage.isTrustedIdentity(this.addr.id, device.identityKey)) {
                getSignalLogger()?.warn('identity-verification-failed', { peerId: this.addr.id })
                throw new UntrustedIdentityKeyError(this.addr.id, device.identityKey)
            }

            // - Verificar resultado da assinatura
            const signatureValid = this.verifySignedPreKeySignature(
                device.identityKey,
                device.signedPreKey.publicKey,
                device.signedPreKey.signature
            )

            if (!signatureValid) {
                throw new Error(
                    `Invalid signature on signedPreKey from ${this.addr}. Possible MITM attack.`
                )
            }

            const baseKey = await this.generateSessionDhKeyPair()

            const session = await this.initSession(
                true,
                { pubKey: baseKey.publicKey, privKey: baseKey.privateKey },
                undefined,
                device.identityKey,
                device.preKey?.publicKey,
                device.signedPreKey.publicKey,
                device.registrationId
            )

            const pendingPreKey: PendingPreKey = {
                baseKey: baseKey.publicKey,
                signedKeyId: device.signedPreKey.keyId
            }
            if (device.preKey) {
                pendingPreKey.preKeyId = device.preKey.keyId
            }
            session.pendingPreKey = pendingPreKey

            let record = await this.storage.loadSession(fqAddr)
            if (!record) {
                record = new SessionRecord()
            } else {
                const openSession = record.getOpenSession()
                if (openSession) record.closeSession(openSession)
            }

            record.setSession(session)
            this.assertNotAborted(signal)
            await this.storage.storeSession(fqAddr, record)
        }, { timeoutMs: 30_000 })
    }

    async initIncoming(
        record: SessionRecord,
        message: PreKeyWhisperMessage
    ): Promise<number | undefined> {
        const fqAddr = this.addr.toString()

        if (!await this.storage.isTrustedIdentity(this.addr.id, message.identityKey)) {
            getSignalLogger()?.warn('identity-verification-failed', { peerId: this.addr.id })
            throw new UntrustedIdentityKeyError(this.addr.id, message.identityKey)
        }

        if (record.getSession(message.baseKey)) {
            return undefined
        }

        const [preKeyPair, signedPreKeyPair] = this.storage.loadPreKeyPair
            ? await this.storage.loadPreKeyPair(message.preKeyId, message.signedPreKeyId)
            : await Promise.all([
                message.preKeyId ? this.storage.loadPreKey(message.preKeyId) : Promise.resolve(undefined),
                this.storage.loadSignedPreKey(message.signedPreKeyId)
            ])

        if (message.preKeyId && !preKeyPair) {
            throw new PreKeyError('Invalid PreKey ID')
        }
        if (!signedPreKeyPair) {
            throw new PreKeyError('Missing SignedPreKey')
        }

        const existingOpenSession = record.getOpenSession()
        if (existingOpenSession) {
            getSignalLogger()?.warn('identity-verification-failed', { peerId: this.addr.id })
            record.closeSession(existingOpenSession)
        }

        const session = await this.initSession(
            false,
            preKeyPair,
            signedPreKeyPair,
            message.identityKey,
            message.baseKey,
            undefined,
            message.registrationId
        )

        record.setSession(session)
        return message.preKeyId
    }

    private async initSession(
        isInitiator: boolean,
        ourEphemeralKey: KeyPair | undefined,
        ourSignedKey: KeyPair | undefined,
        theirIdentityPubKey: Uint8Array,
        theirEphemeralPubKey: Uint8Array | undefined,
        theirSignedPubKey: Uint8Array | undefined,
        registrationId: number
    ): Promise<SessionEntry> {
        // X3DH Protocol (RFC):
        // Initiator: ourIdentity, ourSigned=ourEphemeral, theirIdentity, theirSigned
        // Responder: ourIdentity, ourSigned, theirIdentity, theirSigned=theirEphemeral

        // Para o cálculo DH, adaptamos os papéis conforme o papel na X3DH
        let ourEphemeralForInitSession = ourEphemeralKey
        let theirEphemeralForInitSession = theirEphemeralPubKey

        if (isInitiator) {
            // Initiator: usa ourEphemeral como ourSigned
            ourSignedKey = ourEphemeralKey
        } else {
            // Responder: usa theirEphemeral como theirSigned
            theirSignedPubKey = theirEphemeralPubKey
        }

        const sharedSecretLen = (!ourEphemeralForInitSession || !theirEphemeralForInitSession) ? 128 : 160
        const sharedSecret = new Uint8Array(sharedSecretLen)
        sharedSecret.fill(0xff, 0, 32)

        const ourIdentityKey = await this.storage.getOurIdentity()

        // X3DH variant route B:
        // - identity keys remain Ed25519 for trust/signature verification
        // - DH uses explicit Ed25519->X25519 conversions for identity material
        const ourIdentityDhPriv = this.resolveOurIdentityDhPrivateKey(ourIdentityKey.privKey, ourIdentityKey.pubKey)
        const theirIdentityDhPub = this.resolveTheirIdentityDhPublicKey(theirIdentityPubKey)

        // X3DH DH Calculations (RFC order correto):
        // a1 = DH(ourIdentity, theirSigned)
        const theirSignedDhPub = this.resolveRemoteDhPublicKey(theirSignedPubKey!, 'signed prekey public key')
        const a1 = signalCrypto.calculateAgreement(theirSignedDhPub, ourIdentityDhPriv)

        // a2 = DH(theirIdentity, ourSigned)
        const a2 = signalCrypto.calculateAgreement(theirIdentityDhPub, ourSignedKey!.privKey)

        // a3 = DH(ourSigned, theirSigned)
        const a3 = signalCrypto.calculateAgreement(theirSignedDhPub, ourSignedKey!.privKey)

        // Posição dos valores no shared secret depende de quem é iniciador
        sharedSecret.set(a1, isInitiator ? 32 : 64)
        sharedSecret.set(a2, isInitiator ? 64 : 32)
        sharedSecret.set(a3, 96)

        // a4 = DH(ourEphemeral, theirEphemeral) - apenas quando ambos têm ephemeral
        if (ourEphemeralForInitSession && theirEphemeralForInitSession) {
            const theirEphemeralDhPub = this.resolveRemoteDhPublicKey(
                theirEphemeralForInitSession,
                'ephemeral public key'
            )
            const a4 = signalCrypto.calculateAgreement(theirEphemeralDhPub, ourEphemeralForInitSession.privKey)
            sharedSecret.set(a4, 128)
        }

        const masterKey = this.deriveSecrets(
            sharedSecret,
            zero32(),
            HKDF_INFO_WHISPER_TEXT,
            2
        )

        const session = SessionRecord.createEntry()
        session.registrationId = registrationId

        let resolvedEphemeralKP: KeyPair
        if (isInitiator) {
            const kp = await this.generateSessionDhKeyPair()
            resolvedEphemeralKP = { pubKey: kp.publicKey, privKey: kp.privateKey }
        } else {
            resolvedEphemeralKP = { pubKey: ourSignedKey!.pubKey, privKey: ourSignedKey!.privKey }
        }

        session.currentRatchet = {
            rootKey: masterKey[0]!,
            ephemeralKeyPair: resolvedEphemeralKP,
            lastRemoteEphemeralKey: theirSignedPubKey!,
            previousCounter: 0
        }

        session.indexInfo = {
            created: Date.now(),
            used: Date.now(),
            remoteIdentityKey: theirIdentityPubKey,
            baseKey: isInitiator ? ourEphemeralKey!.pubKey : theirEphemeralPubKey!,
            baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
            closed: -1
        }

        if (isInitiator) {
            this.calculateSendingRatchet(session, theirSignedPubKey!)
        }

        return session
    }

    private calculateSendingRatchet(session: SessionEntry, remoteKey: Uint8Array): void {
        const ratchet = session.currentRatchet
        const remoteDhKey = this.resolveRemoteDhPublicKey(remoteKey, 'ratchet remote key')
        const sharedSecret = signalCrypto.calculateAgreement(
            remoteDhKey,
            ratchet.ephemeralKeyPair.privKey
        )

        const masterKey = this.deriveSecrets(
            sharedSecret,
            ratchet.rootKey,
            HKDF_INFO_RATCHET,
            2
        )

        session.addChain(ratchet.ephemeralKeyPair.pubKey, {
            messageKeys: new Map(),
            chainKey: {
                counter: -1,
                key: masterKey[1]!
            },
            chainType: ChainType.SENDING
        })

        ratchet.rootKey = masterKey[0]!
    }

    private deriveSecrets(
        input: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        chunks: number = 3
    ): Uint8Array[] {
        const hkdf = crypto.hkdf(input, salt, info, { length: chunks * 32 })
        const result: Uint8Array[] = []
        for (let i = 0; i < chunks; i++) {
            result.push(hkdf.subarray(i * 32, (i + 1) * 32))
        }
        return result
    }

    private resolveOurIdentityDhPrivateKey(identityPrivateKey: Uint8Array, identityPublicKey?: Uint8Array): Uint8Array {
        if (identityPrivateKey.length === 64) {
            try {
                return signalCrypto.convertIdentityPrivateToX25519(identityPrivateKey)
            } catch (error) {
                throw new Error('X3DH strict mode rejected local identity private key conversion (Ed25519->X25519 failed)', {
                    cause: error instanceof Error ? error : undefined
                })
            }
        }

        if (identityPrivateKey.length === 32) {
            if (this.isPrefixedCurvePublicKey(identityPublicKey)) {
                return identityPrivateKey
            }

            if (this.compatMode === 'legacy') {
                this.warnLegacyDowngradeOnce('using raw local X25519 identity private key (interop fallback)')
                return identityPrivateKey
            }

            throw new Error('X3DH strict mode requires a 64-byte Ed25519 local identity private key')
        }

        throw new Error(`Invalid local identity private key length for X3DH: ${identityPrivateKey.length}`)
    }

    private resolveTheirIdentityDhPublicKey(theirIdentityPubKey: Uint8Array): Uint8Array {
        if (this.isPrefixedCurvePublicKey(theirIdentityPubKey)) {
            return theirIdentityPubKey.subarray(1)
        }

        if (theirIdentityPubKey.length !== 32) {
            throw new Error(`Invalid remote identity public key length for X3DH: ${theirIdentityPubKey.length}`)
        }

        try {
            return signalCrypto.convertIdentityPublicToX25519(theirIdentityPubKey)
        } catch (error) {
            if (this.compatMode === 'legacy') {
                this.warnLegacyDowngradeOnce('using raw remote identity key as X25519 (interop fallback)')
                return theirIdentityPubKey
            }

            throw new Error('X3DH strict mode rejected remote identity key conversion (Ed25519->X25519 failed)', {
                cause: error instanceof Error ? error : undefined
            })
        }
    }

    private verifySignedPreKeySignature(
        identityKey: Uint8Array,
        signedPreKeyPublicKey: Uint8Array,
        signature: Uint8Array
    ): boolean {
        if (!(signature instanceof Uint8Array) || signature.length !== 64) {
            return false
        }

        if (this.isPrefixedCurvePublicKey(identityKey)) {
            return this.verifyLegacyCurveSignature(identityKey, signedPreKeyPublicKey, signature)
        }

        try {
            return signalCrypto.verify(identityKey, signedPreKeyPublicKey, signature)
        } catch {
            if (this.compatMode !== 'legacy') {
                return false
            }
            return this.verifyLegacyCurveSignature(identityKey, signedPreKeyPublicKey, signature)
        }
    }

    private verifyLegacyCurveSignature(
        identityKey: Uint8Array,
        signedPreKeyPublicKey: Uint8Array,
        signature: Uint8Array
    ): boolean {
        try {
            const legacyPub = this.normalizeCurvePublicKey(signedPreKeyPublicKey)
            return verifyCurveSignature(toBufferView(identityKey), toBufferView(legacyPub), signature, false)
        } catch {
            return false
        }
    }

    private isPrefixedCurvePublicKey(value: Uint8Array | undefined): boolean {
        return value instanceof Uint8Array && value.length === 33 && value[0] === 0x05
    }

    private normalizeCurvePublicKey(publicKey: Uint8Array): Uint8Array {
        if (this.isPrefixedCurvePublicKey(publicKey)) {
            return publicKey
        }
        if (publicKey.length === 32) {
            const prefixed = new Uint8Array(33)
            prefixed[0] = 0x05
            prefixed.set(publicKey, 1)
            return prefixed
        }
        throw new Error(`Invalid curve public key length: ${publicKey.length}`)
    }

    private resolveRemoteDhPublicKey(publicKey: Uint8Array, label: string): Uint8Array {
        if (this.isPrefixedCurvePublicKey(publicKey)) {
            return publicKey.subarray(1)
        }
        if (publicKey.length === 32) {
            return publicKey
        }
        throw new Error(`Invalid ${label} length for X25519 DH: ${publicKey.length}`)
    }

    private async generateSessionDhKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
        if (this.compatMode === 'legacy') {
            const legacy = generateLegacyCurveKeyPair()
            return {
                publicKey: legacy.pubKey,
                privateKey: legacy.privKey
            }
        }
        return signalCrypto.generateDHKeyPair()
    }

    private warnLegacyDowngradeOnce(reason: string): void {
        if (this.legacyWarningEmitted) return
        this.legacyWarningEmitted = true
        getSignalLogger()?.warn('compat-fallback-used', {
            component: 'session-builder',
            peerId: this.addr.id,
            reason
        })
        this.warnCompat(`[swt-libsignal][x3dh][legacy] ${reason}`)
    }
}

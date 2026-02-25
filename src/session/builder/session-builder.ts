import { BaseKeyType, ChainType } from "../../ratchet-types"
import type { ProtocolAddress } from '../../protocol_address'
import { SessionRecord, SessionEntry, type PendingPreKey } from '../record/index'
import { crypto } from '../../crypto'
import { signalCrypto } from '../../curve'
import { UntrustedIdentityKeyError, PreKeyError } from '../../signal-errors'
import { enqueue } from '../../job_queue'
import { getSignalLogger } from '../../internal/logger'

import type {
    PreKeyBundle,
    PreKeyWhisperMessage,
    SessionBuilderStorage,
    KeyPair
} from './types'

import { HKDF_INFO_WHISPER_TEXT, TEXT_ENCODER, zero32 } from '../../internal/constants/crypto'

const HKDF_INFO_RATCHET = TEXT_ENCODER.encode('WhisperRatchet')

export class SessionBuilder {
    private readonly addr: ProtocolAddress
    private readonly storage: SessionBuilderStorage

    private assertNotAborted(signal: AbortSignal): void {
        if (signal.aborted) {
            const reason = signal.reason
            throw reason instanceof Error ? reason : new Error('Operation aborted')
        }
    }

    constructor(storage: SessionBuilderStorage, protocolAddress: ProtocolAddress) {
        this.addr = protocolAddress
        this.storage = storage
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
            const signatureValid = signalCrypto.verify(
                device.identityKey,
                device.signedPreKey.publicKey,
                device.signedPreKey.signature
            )

            if (!signatureValid) {
                throw new Error(
                    `Invalid signature on signedPreKey from ${this.addr}. Possible MITM attack.`
                )
            }

            const baseKey = await signalCrypto.generateDHKeyPair()

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
        const ourIdentityDhPriv = ourIdentityKey.privKey.length === 64
            ? signalCrypto.convertIdentityPrivateToX25519(ourIdentityKey.privKey)
            : ourIdentityKey.privKey

        let theirIdentityDhPub = theirIdentityPubKey
        try {
            theirIdentityDhPub = signalCrypto.convertIdentityPublicToX25519(theirIdentityPubKey)
        } catch {
            // Legacy mode: some educational setups persist identity directly as X25519.
            theirIdentityDhPub = theirIdentityPubKey
        }

        // X3DH DH Calculations (RFC order correto):
        // a1 = DH(ourIdentity, theirSigned)
        const a1 = signalCrypto.calculateAgreement(theirSignedPubKey!, ourIdentityDhPriv)

        // a2 = DH(theirIdentity, ourSigned)
        const a2 = signalCrypto.calculateAgreement(theirIdentityDhPub, ourSignedKey!.privKey)

        // a3 = DH(ourSigned, theirSigned)
        const a3 = signalCrypto.calculateAgreement(theirSignedPubKey!, ourSignedKey!.privKey)

        // Posição dos valores no shared secret depende de quem é iniciador
        sharedSecret.set(a1, isInitiator ? 32 : 64)
        sharedSecret.set(a2, isInitiator ? 64 : 32)
        sharedSecret.set(a3, 96)

        // a4 = DH(ourEphemeral, theirEphemeral) - apenas quando ambos têm ephemeral
        if (ourEphemeralForInitSession && theirEphemeralForInitSession) {
            const a4 = signalCrypto.calculateAgreement(theirEphemeralForInitSession, ourEphemeralForInitSession.privKey)
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
            const kp = await signalCrypto.generateDHKeyPair()
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
        const sharedSecret = signalCrypto.calculateAgreement(
            remoteKey,
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
}
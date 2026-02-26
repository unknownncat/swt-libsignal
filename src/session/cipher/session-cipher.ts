import { PROTOCOL_VERSION } from '../constants'
import type {
    EncryptResult,
    DecryptWithSessionResult,
    SessionCipherStorage,
    WhisperMessageProto,
    PreKeyWhisperMessageProto,
    SessionCipherOptions
} from './types'
import { WhisperMessageEncoder } from './encoding'
import { assertUint8, toBase64 } from '../utils'

import { ChainType } from "../../ratchet-types"
import { ProtocolAddress } from '../../protocol_address'
import { SessionBuilder } from '../builder/session-builder'
import { SessionRecord, type SessionEntry, type ChainState } from '../record/index'
import { crypto } from '../../crypto'
import { signalCrypto } from '../../curve'
import { SessionError, SessionDecryptFailed, SessionStateError, UntrustedIdentityKeyError, MessageCounterError } from '../../signal-errors'
import { generateKeyPair as generateLegacyCurveKeyPair } from '../../compat/libsignal/src/curve'
import { enqueue } from '../../job_queue'
import { getSignalLogger } from '../../internal/logger'
import { TEXT_ENCODER, zero32 } from '../../internal/constants/crypto'
import {
    CbcHmacSuite,
    buildDecryptTransportMacInput,
    buildMessageMetadata,
    buildTransportMacInput
} from './crypto-suite'
import type { CompatMode } from '../builder/types'
import type { CryptoSuite } from './crypto-suite'

const HKDF_INFO_MESSAGE_KEYS = TEXT_ENCODER.encode('WhisperMessageKeys')
const HKDF_INFO_RATCHET = TEXT_ENCODER.encode('WhisperRatchet')
const HMAC_DERIVE_MESSAGE_KEY = Uint8Array.of(1)
const HMAC_DERIVE_CHAIN_KEY = Uint8Array.of(2)
const MAX_MESSAGE_KEYS_PER_CHAIN = 2_000
const MAX_MESSAGE_KEYS_PER_SESSION = 8_000

export class SessionCipher {
    private readonly addr: ProtocolAddress
    private readonly addrStr: string
    private readonly storage: SessionCipherStorage
    private readonly compatMode: CompatMode
    private readonly cryptoSuite: CryptoSuite
    private readonly warnCompat: (message: string) => void
    private warnedLegacyCbcHmac = false

    constructor(storage: SessionCipherStorage, protocolAddress: ProtocolAddress, options: SessionCipherOptions = {}) {
        if (!(protocolAddress instanceof ProtocolAddress)) {
            throw new TypeError('protocolAddress must be a ProtocolAddress')
        }
        this.addr = protocolAddress
        this.addrStr = protocolAddress.toString()
        this.storage = storage
        this.compatMode = options.compatMode ?? 'strict'
        this.cryptoSuite = options.cryptoSuite ?? CbcHmacSuite
        this.warnCompat = options.warn ?? ((message: string) => { console.warn(message) })
        this.warnLegacyCbcHmacUsageOnce()
    }

    toString(): string {
        return `<SessionCipher(${this.addrStr})>`
    }

    private warnLegacyCbcHmacUsageOnce(): void {
        if (this.warnedLegacyCbcHmac) return
        if (this.compatMode !== 'legacy') return
        if (this.cryptoSuite.name !== 'cbc-hmac') return
        this.warnedLegacyCbcHmac = true
        this.warnCompat('[swt-libsignal][session] cbc-hmac cryptoSuite with legacy compatMode increases downgrade/interoperability risk; prefer compatMode=\"strict\".')
    }

    private _encodeTupleByte(n1: number, n2: number): number {
        if (n1 > 15 || n2 > 15) throw new TypeError('Numbers must be 4 bits or less')
        return (n1 << 4) | n2
    }

    private _decodeTupleByte(byte: number): [number, number] {
        return [byte >> 4, byte & 0xf]
    }

    private async getRecord(): Promise<SessionRecord | undefined> {
        const record = await this.storage.loadSession(this.addrStr)
        if (record && !(record instanceof SessionRecord)) {
            throw new TypeError('SessionRecord type expected from loadSession')
        }
        return record
    }

    private async storeRecord(record: SessionRecord): Promise<void> {
        record.removeOldSessions()
        await this.storage.storeSession(this.addrStr, record)
    }

    private assertNotAborted(signal: AbortSignal): void {
        if (signal.aborted) {
            const reason = signal.reason
            throw reason instanceof Error ? reason : new Error('Operation aborted')
        }
    }

    private async queueJob<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
        return enqueue(this.addrStr, fn, { timeoutMs: 30_000 })
    }

    async encrypt(data: Uint8Array): Promise<EncryptResult> {
        assertUint8(data)
        const ourIdentity = await this.storage.getOurIdentity()

        return this.queueJob(async (signal) => {
            const record = await this.getRecord()
            if (!record) throw new SessionError('No sessions')

            const session = record.getOpenSession()
            if (!session) throw new SessionError('No open session')

            const remoteIdentityKey = session.indexInfo.remoteIdentityKey
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                getSignalLogger()?.warn('identity-verification-failed', { peerId: this.addr.id })
                throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey)
            }

            const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey)
            if (!chain || chain.chainType === ChainType.RECEIVING) {
                throw new SessionStateError('Tried to encrypt on a receiving chain')
            }

            this.fillMessageKeys(chain, chain.chainKey.counter + 1)

            const messageKey = chain.messageKeys.get(chain.chainKey.counter)
            if (!messageKey) throw new Error('Message key not generated')

            const keys = this.deriveSecrets(messageKey, zero32(), HKDF_INFO_MESSAGE_KEYS)

            const [cipherKey, macKey, aadKey] = keys
            // Validação extra - deriveSecrets garante tamanho, mas checamos mesmo assim
            if (!cipherKey || !macKey || !aadKey || cipherKey.length !== 32 || macKey.length !== 32 || aadKey.length !== 32) {
                throw new Error('Invalid key derivation')
            }

            let result: EncryptResult
            try {
                const versionByte = this._encodeTupleByte(PROTOCOL_VERSION, PROTOCOL_VERSION)
                const messageMeta = {
                    ephemeralKey: session.currentRatchet.ephemeralKeyPair.pubKey,
                    counter: chain.chainKey.counter,
                    previousCounter: session.currentRatchet.previousCounter
                }
                const associatedData = this.cryptoSuite.buildAssociatedData({
                    senderIdentityKey: ourIdentity.pubKey,
                    receiverIdentityKey: remoteIdentityKey,
                    versionByte,
                    message: messageMeta,
                    aadKey
                })
                const packedCiphertext = this.cryptoSuite.encryptPayload({
                    cipherKey,
                    macKey,
                    plaintext: data,
                    associatedData
                })

                const msg: WhisperMessageProto = {
                    ephemeralKey: messageMeta.ephemeralKey,
                    counter: messageMeta.counter,
                    previousCounter: messageMeta.previousCounter,
                    ciphertext: packedCiphertext
                }

                const msgBuf = WhisperMessageEncoder.encodeWhisperMessage(msg)
                const macInput = buildTransportMacInput(
                    ourIdentity.pubKey,
                    remoteIdentityKey,
                    versionByte,
                    msgBuf
                )
                const mac = this.cryptoSuite.mac(macKey, macInput, 8)

                const body = new Uint8Array(msgBuf.byteLength + 9)
                body[0] = versionByte
                body.set(msgBuf, 1)
                body.set(mac.subarray(0, 8), msgBuf.byteLength + 1)

                if (session.pendingPreKey) {
                    const preKeyMsg: PreKeyWhisperMessageProto = {
                        identityKey: ourIdentity.pubKey,
                        registrationId: await this.storage.getOurRegistrationId(),
                        baseKey: session.pendingPreKey.baseKey,
                        signedPreKeyId: session.pendingPreKey.signedKeyId,
                        preKeyId: session.pendingPreKey.preKeyId!,
                        message: body
                    }

                    const preKeyBuf = WhisperMessageEncoder.encodePreKeyWhisperMessage(preKeyMsg)
                    const finalBody = new Uint8Array(1 + preKeyBuf.byteLength)
                    finalBody[0] = versionByte
                    finalBody.set(preKeyBuf, 1)

                    result = { type: 3, body: finalBody, registrationId: session.registrationId }
                } else {
                    result = { type: 1, body, registrationId: session.registrationId }
                }
            } finally {
                // DELETE ALWAYS - mesmo em caso de erro
                // Garante forward secrecy: message key nunca será reutilizado
                chain.messageKeys.delete(chain.chainKey.counter)
            }

            // Persistir APÓS deletar message key
            this.assertNotAborted(signal)
            await this.storeRecord(record)
            return result
        })
    }

    async decryptWhisperMessage(data: Uint8Array): Promise<Uint8Array> {
        assertUint8(data)
        return this.queueJob(async (signal) => {
            const record = await this.getRecord()
            if (!record) throw new SessionError('No session record')

            const result = await this.decryptWithSessions(data, record.getSessions())
            const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey

            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                getSignalLogger()?.warn('identity-verification-failed', { peerId: this.addr.id })
                throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey)
            }

            this.assertNotAborted(signal)
            await this.storeRecord(record)
            return result.plaintext
        })
    }

    async decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Uint8Array> {
        assertUint8(data)
        if (!data[0]) throw new Error('Invalid PreKeyWhisperMessage')

        const versions = this._decodeTupleByte(data[0])
        if (versions[1] > PROTOCOL_VERSION || versions[0] < PROTOCOL_VERSION) {
            throw new Error('Incompatible version number on PreKeyWhisperMessage')
        }

        return this.queueJob(async (signal) => {
            let record = await this.getRecord()
            const preKeyProto = WhisperMessageEncoder.decodePreKeyWhisperMessage(data.subarray(1))

            // Validar campos obrigatórios
            if (!preKeyProto.identityKey || preKeyProto.identityKey.length === 0) {
                throw new Error('Missing or empty identityKey in PreKeyWhisperMessage')
            }
            if (!preKeyProto.baseKey || preKeyProto.baseKey.length === 0) {
                throw new Error('Missing or empty baseKey in PreKeyWhisperMessage')
            }
            if (!preKeyProto.message || preKeyProto.message.length === 0) {
                throw new Error('Missing or empty message in PreKeyWhisperMessage')
            }
            if (preKeyProto.signedPreKeyId == null) {
                throw new Error('Missing signedPreKeyId in PreKeyWhisperMessage')
            }
            if (preKeyProto.registrationId == null) {
                throw new Error('Missing registrationId in PreKeyWhisperMessage')
            }

            if (!record) {
                record = new SessionRecord()
            }

            const builder = new SessionBuilder(this.storage, this.addr, {
                compatMode: this.compatMode,
                warn: this.warnCompat
            })
            const preKeyId = await builder.initIncoming(record, preKeyProto)

            const session = record.getSession(preKeyProto.baseKey)
            if (!session) throw new SessionError('Session not initialized')

            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session)

            this.assertNotAborted(signal)
            if (preKeyId && this.storage.storeSessionAndRemovePreKey) {
                await this.storage.storeSessionAndRemovePreKey(this.addrStr, record, preKeyId)
            } else {
                await this.storeRecord(record)
                if (preKeyId) await this.storage.removePreKey(preKeyId)
            }

            return plaintext
        })
    }

    async hasOpenSession(): Promise<boolean> {
        return this.queueJob(async (signal) => {
            const record = await this.getRecord()
            return !!record && record.haveOpenSession()
        })
    }

    async closeOpenSession(): Promise<void> {
        return this.queueJob(async (signal) => {
            const record = await this.getRecord()
            if (record) {
                const open = record.getOpenSession()
                if (open) {
                    record.closeSession(open)
                    this.assertNotAborted(signal)
                    await this.storeRecord(record)
                }
            }
        })
    }

    private async decryptWithSessions(
        data: Uint8Array,
        sessions: SessionEntry[]
    ): Promise<DecryptWithSessionResult> {
        if (!sessions.length) throw new SessionError('No sessions available')

        const errors: Array<{ sessionKey: string; error: Error }> = []

        for (let i = 0; i < sessions.length; i++) {
            const session = sessions[i]!
            const sessionKey = toBase64(session.indexInfo.baseKey)

            try {
                const plaintext = await this.doDecryptWhisperMessage(data, session)
                const usedAt = Date.now()
                session.indexInfo.used = usedAt
                return { session, plaintext }
            } catch (e) {
                errors.push({
                    sessionKey,
                    error: e instanceof Error ? e : new Error(String(e))
                })
            }
        }

        throw new SessionDecryptFailed(
            `Failed to decrypt message for ${this.addr.id} with available sessions`,
            { cause: errors[0]?.error }
        )
    }

    private async doDecryptWhisperMessage(
        messageBuffer: Uint8Array,
        session: SessionEntry
    ): Promise<Uint8Array> {
        assertUint8(messageBuffer)
        if (!messageBuffer[0]) throw new Error('Invalid WhisperMessage')

        const versions = this._decodeTupleByte(messageBuffer[0])
        if (versions[1] > PROTOCOL_VERSION || versions[0] < PROTOCOL_VERSION) {
            throw new Error('Incompatible version number on WhisperMessage')
        }

        const messageEnd = messageBuffer.byteLength - 8
        const messageProto = messageBuffer.subarray(1, messageEnd)
        const message = WhisperMessageEncoder.decodeWhisperMessage(messageProto)

        // Transactional decrypt: mutate only the snapshot and commit atomically at the end.
        const snapshot = session.clone()

        await this.maybeStepRatchet(snapshot, message.ephemeralKey, message.previousCounter)

        const chain = snapshot.getChain(message.ephemeralKey)
        if (!chain || chain.chainType === ChainType.SENDING) {
            throw new SessionStateError('Tried to decrypt on a sending chain')
        }

        this.fillMessageKeys(chain, message.counter)

        if (!chain.messageKeys.has(message.counter)) {
            throw new MessageCounterError('Key used already or never filled')
        }

        const messageKey = chain.messageKeys.get(message.counter)!

        const keys = this.deriveSecrets(
            messageKey,
            zero32(),
            HKDF_INFO_MESSAGE_KEYS
        )

        const ourIdentity = await this.storage.getOurIdentity()
        const versionByte = this._encodeTupleByte(PROTOCOL_VERSION, PROTOCOL_VERSION)
        const transport = buildDecryptTransportMacInput(
            snapshot.indexInfo.remoteIdentityKey,
            ourIdentity.pubKey,
            versionByte,
            messageBuffer
        )
        const associatedData = this.cryptoSuite.buildAssociatedData({
            senderIdentityKey: snapshot.indexInfo.remoteIdentityKey,
            receiverIdentityKey: ourIdentity.pubKey,
            versionByte,
            message: buildMessageMetadata(message),
            aadKey: keys[2]!
        })

        const mac = messageBuffer.subarray(-8)

        this.verifyMAC(transport.macInput, keys[1]!, mac, 8)
        const plaintext = this.cryptoSuite.decryptPayload({
            cipherKey: keys[0]!,
            macKey: keys[1]!,
            payload: message.ciphertext,
            associatedData
        })

        chain.messageKeys.delete(message.counter)
        this.enforceMessageKeyBudget(snapshot)

        delete snapshot.pendingPreKey
        session.replaceWith(snapshot)
        return plaintext
    }

    private fillMessageKeys(chain: ChainState, targetCounter: number): void {
        if (chain.chainKey.counter >= targetCounter) return

        const maxFutureMessages = MAX_MESSAGE_KEYS_PER_CHAIN
        const newMessages = targetCounter - chain.chainKey.counter

        //- Validar limite de mensagens futuras
        if (newMessages > maxFutureMessages) {
            throw new SessionError(
                `Over ${maxFutureMessages} messages into the future: ${newMessages} messages`
            )
        }

        //- Verificar overflow de counter
        if (targetCounter > Number.MAX_SAFE_INTEGER - 1000) {
            throw new SessionError(
                `Counter would overflow: current=${chain.chainKey.counter}, target=${targetCounter}`
            )
        }

        if (chain.chainKey.key === undefined) {
            throw new SessionError('Chain closed')
        }

        let key = chain.chainKey.key
        let counter = chain.chainKey.counter

        while (counter < targetCounter) {
            counter++
            chain.messageKeys.set(counter, crypto.hmacSha256(key, HMAC_DERIVE_MESSAGE_KEY))
            key = crypto.hmacSha256(key, HMAC_DERIVE_CHAIN_KEY)
        }

        chain.chainKey.key = key
        chain.chainKey.counter = counter
    }

    private enforceMessageKeyBudget(session: SessionEntry): void {
        let totalKeys = 0
        const globalOrder: Array<{ chain: ChainState; counter: number }> = []

        for (const [, chain] of session.chains()) {
            totalKeys += chain.messageKeys.size

            while (chain.messageKeys.size > MAX_MESSAGE_KEYS_PER_CHAIN) {
                const oldestCounter = chain.messageKeys.keys().next().value as number | undefined
                if (oldestCounter === undefined) break
                chain.messageKeys.delete(oldestCounter)
                totalKeys -= 1
            }

            for (const counter of chain.messageKeys.keys()) {
                globalOrder.push({ chain, counter })
            }
        }

        if (totalKeys <= MAX_MESSAGE_KEYS_PER_SESSION) return

        let toEvict = totalKeys - MAX_MESSAGE_KEYS_PER_SESSION
        for (let i = 0; i < globalOrder.length && toEvict > 0; i++) {
            const item = globalOrder[i]!
            if (!item.chain.messageKeys.delete(item.counter)) continue
            toEvict -= 1
        }
    }

    private async maybeStepRatchet(
        session: SessionEntry,
        remoteKey: Uint8Array,
        previousCounter: number
    ): Promise<void> {
        if (session.getChain(remoteKey)) return

        const ratchet = session.currentRatchet
        const previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey)

        if (previousRatchet) {
            this.fillMessageKeys(previousRatchet, previousCounter)
            previousRatchet.chainKey.key = undefined
        }

        this.calculateRatchet(session, remoteKey, false)

        const prevChain = session.getChain(ratchet.ephemeralKeyPair.pubKey)
        if (prevChain) {
            ratchet.previousCounter = prevChain.chainKey.counter
            session.deleteChain(ratchet.ephemeralKeyPair.pubKey)
        }

        const newKp = this.compatMode === 'legacy'
            ? (() => {
                const legacy = generateLegacyCurveKeyPair()
                return { publicKey: legacy.pubKey, privateKey: legacy.privKey }
            })()
            : await signalCrypto.generateDHKeyPair()
        ratchet.ephemeralKeyPair = {
            pubKey: newKp.publicKey,
            privKey: newKp.privateKey
        }

        this.calculateRatchet(session, remoteKey, true)
        ratchet.lastRemoteEphemeralKey = remoteKey
        getSignalLogger()?.debug('ratchet-rotate', {
            peerId: this.addr.id,
            previousCounter: ratchet.previousCounter,
            remoteKeyLength: remoteKey.length
        })
    }

    private calculateRatchet(session: SessionEntry, remoteKey: Uint8Array, sending: boolean): void {
        const ratchet = session.currentRatchet
        const remoteDhKey = this.resolveRemoteDhPublicKey(remoteKey)
        const sharedSecret = signalCrypto.calculateAgreement(remoteDhKey, ratchet.ephemeralKeyPair.privKey)

        const masterKeys = this.deriveSecrets(
            sharedSecret,
            ratchet.rootKey,
            HKDF_INFO_RATCHET,
            2
        )

        const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey

        session.addChain(chainKey, {
            messageKeys: new Map(),
            chainKey: { counter: -1, key: masterKeys[1]! },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
        })

        ratchet.rootKey = masterKeys[0]!
    }

    private resolveRemoteDhPublicKey(remoteKey: Uint8Array): Uint8Array {
        if (remoteKey.length === 33 && remoteKey[0] === 0x05) {
            return remoteKey.subarray(1)
        }
        if (remoteKey.length === 32) {
            return remoteKey
        }
        throw new Error(`Invalid remote ratchet key length for X25519 DH: ${remoteKey.length}`)
    }

    private deriveSecrets(
        input: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        chunks: number = 3
    ): Uint8Array[] {
        const expectedLength = chunks * 32
        const hkdf = crypto.hkdf(input, salt, info, { length: expectedLength })

        if (hkdf.length !== expectedLength) {
            throw new Error(
                `HKDF derivation failed: expected ${expectedLength} bytes, got ${hkdf.length}`
            )
        }

        const result: Uint8Array[] = []
        for (let i = 0; i < chunks; i++) {
            const key = hkdf.subarray(i * 32, (i + 1) * 32)
            if (key.length !== 32) {
                throw new Error(
                    `Invalid key derivation at chunk ${i}: expected 32 bytes, got ${key.length}`
                )
            }
            result.push(key)
        }
        return result
    }

    private verifyMAC(macInput: Uint8Array, key: Uint8Array, mac: Uint8Array, length: number): void {
        this.cryptoSuite.verifyMac(key, macInput, mac, length)
    }
}

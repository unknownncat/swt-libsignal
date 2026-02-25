import { createCipheriv, createDecipheriv } from 'node:crypto'
import { SenderKeyMessage } from './sender-key-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'
import { SenderKeyState } from './sender-key-state'

export interface SenderKeyStore {
    loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
    storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

function toBufferView(data: Uint8Array): Buffer {
    return Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

export class GroupCipher {
    private readonly senderKeyStore: SenderKeyStore
    private readonly senderKeyName: SenderKeyName

    constructor(senderKeyStore: SenderKeyStore, senderKeyName: SenderKeyName) {
        this.senderKeyStore = senderKeyStore
        this.senderKeyName = senderKeyName
    }

    async encrypt(paddedPlaintext: Uint8Array): Promise<Uint8Array> {
        const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
        const senderKeyState = record.getSenderKeyState()
        if (!senderKeyState) {
            throw new Error('No sender key state to encrypt message')
        }

        const iteration = senderKeyState.getSenderChainKey().getIteration()
        const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1)
        const signingKeyPrivate = senderKeyState.getSigningKeyPrivate()
        if (!signingKeyPrivate) {
            throw new Error('Missing sender signing private key')
        }

        const ciphertext = this.getCipherText(
            senderKey.getIv(),
            senderKey.getCipherKey(),
            paddedPlaintext
        )

        const senderKeyMessage = new SenderKeyMessage(
            senderKeyState.getKeyId(),
            senderKey.getIteration(),
            ciphertext,
            signingKeyPrivate
        )

        await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
        return senderKeyMessage.serialize()
    }

    async decrypt(senderKeyMessageBytes: Uint8Array): Promise<Uint8Array> {
        const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
        const senderKeyMessage = new SenderKeyMessage(undefined, undefined, undefined, undefined, senderKeyMessageBytes)
        const senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId())
        if (!senderKeyState) {
            throw new Error('No sender key state to decrypt message')
        }

        senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic())
        const senderKey = this.getSenderKey(senderKeyState, senderKeyMessage.getIteration())

        const plaintext = this.getPlainText(
            senderKey.getIv(),
            senderKey.getCipherKey(),
            senderKeyMessage.getCipherText()
        )

        await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
        return plaintext
    }

    private getSenderKey(senderKeyState: SenderKeyState, iteration: number) {
        let senderChainKey = senderKeyState.getSenderChainKey()
        if (senderChainKey.getIteration() > iteration) {
            if (senderKeyState.hasSenderMessageKey(iteration)) {
                const messageKey = senderKeyState.removeSenderMessageKey(iteration)
                if (!messageKey) throw new Error('No sender message key for iteration')
                return messageKey
            }
            throw new Error(`Received message with old counter: ${senderChainKey.getIteration()}, ${iteration}`)
        }

        if (iteration - senderChainKey.getIteration() > 2000) {
            throw new Error('Over 2000 messages into the future')
        }

        while (senderChainKey.getIteration() < iteration) {
            senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey())
            senderChainKey = senderChainKey.getNext()
        }

        senderKeyState.setSenderChainKey(senderChainKey.getNext())
        return senderChainKey.getSenderMessageKey()
    }

    private getPlainText(iv: Uint8Array, key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        try {
            const decipher = createDecipheriv('aes-256-cbc', toBufferView(key), toBufferView(iv))
            const plaintext = Buffer.concat([
                decipher.update(toBufferView(ciphertext)),
                decipher.final()
            ])
            return new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength)
        } catch {
            throw new Error('Invalid group message ciphertext')
        }
    }

    private getCipherText(iv: Uint8Array, key: Uint8Array, plaintext: Uint8Array): Uint8Array {
        try {
            const cipher = createCipheriv('aes-256-cbc', toBufferView(key), toBufferView(iv))
            const ciphertext = Buffer.concat([
                cipher.update(toBufferView(plaintext)),
                cipher.final()
            ])
            return new Uint8Array(ciphertext.buffer, ciphertext.byteOffset, ciphertext.byteLength)
        } catch {
            throw new Error('Invalid group message plaintext')
        }
    }
}

import {
    generateSenderKey,
    generateSenderKeyId,
    generateSenderSigningKey
} from './keyhelper'
import { SenderKeyDistributionMessage } from './sender-key-distribution-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'

export interface SenderKeyStore {
    loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
    storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

export class GroupSessionBuilder {
    private readonly senderKeyStore: SenderKeyStore

    constructor(senderKeyStore: SenderKeyStore) {
        this.senderKeyStore = senderKeyStore
    }

    async process(
        senderKeyName: SenderKeyName,
        senderKeyDistributionMessage: SenderKeyDistributionMessage
    ): Promise<void> {
        const senderKeyRecord = await this.senderKeyStore.loadSenderKey(senderKeyName)
        senderKeyRecord.addSenderKeyState(
            senderKeyDistributionMessage.getId(),
            senderKeyDistributionMessage.getIteration(),
            senderKeyDistributionMessage.getChainKey(),
            senderKeyDistributionMessage.getSignatureKey()
        )
        await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)
    }

    async create(senderKeyName: SenderKeyName): Promise<SenderKeyDistributionMessage> {
        const senderKeyRecord = await this.senderKeyStore.loadSenderKey(senderKeyName)

        if (senderKeyRecord.isEmpty()) {
            const keyId = generateSenderKeyId()
            const senderKey = generateSenderKey()
            const signingKey = await generateSenderSigningKey()

            senderKeyRecord.setSenderKeyState(keyId, 0, senderKey, signingKey)
            await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)
        }

        const state = senderKeyRecord.getSenderKeyState()
        if (!state) {
            throw new Error('No sender key state available')
        }

        return new SenderKeyDistributionMessage(
            state.getKeyId(),
            state.getSenderChainKey().getIteration(),
            state.getSenderChainKey().getSeed(),
            state.getSigningKeyPublic()
        )
    }
}

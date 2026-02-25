import { SenderChainKey } from './sender-chain-key'
import { SenderMessageKey } from './sender-message-key'

interface SenderChainKeyStructure {
    iteration: number
    seed: string
}

interface SenderSigningKeyStructure {
    public: string
    private?: string
}

interface SenderMessageKeyStructure {
    iteration: number
    seed: string
}

export interface SenderKeyStateStructure {
    senderKeyId: number
    senderChainKey: SenderChainKeyStructure
    senderSigningKey: SenderSigningKeyStructure
    senderMessageKeys: SenderMessageKeyStructure[]
}

const u8 = {
    encode: (value: Uint8Array): string => Buffer.from(value).toString('base64'),
    decode: (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64'))
}

export class SenderKeyState {
    private readonly MAX_MESSAGE_KEYS = 2000
    private readonly structure: SenderKeyStateStructure

    constructor(
        id?: number,
        iteration?: number,
        chainKey?: Uint8Array,
        signatureKeyPair?: { public: Uint8Array; private: Uint8Array },
        signatureKeyPublic?: Uint8Array,
        signatureKeyPrivate?: Uint8Array,
        structure?: SenderKeyStateStructure
    ) {
        if (structure) {
            this.structure = {
                ...structure,
                senderMessageKeys: Array.isArray(structure.senderMessageKeys)
                    ? structure.senderMessageKeys
                    : []
            }
            return
        }

        if (signatureKeyPair) {
            signatureKeyPublic = signatureKeyPair.public
            signatureKeyPrivate = signatureKeyPair.private
        }

        this.structure = {
            senderKeyId: id ?? 0,
            senderChainKey: {
                iteration: iteration ?? 0,
                seed: u8.encode(chainKey ?? new Uint8Array(0))
            },
            senderSigningKey: {
                public: u8.encode(signatureKeyPublic ?? new Uint8Array(0)),
                ...(signatureKeyPrivate ? { private: u8.encode(signatureKeyPrivate) } : {})
            },
            senderMessageKeys: []
        }
    }

    getKeyId(): number {
        return this.structure.senderKeyId
    }

    getSenderChainKey(): SenderChainKey {
        return new SenderChainKey(
            this.structure.senderChainKey.iteration,
            u8.decode(this.structure.senderChainKey.seed)
        )
    }

    setSenderChainKey(chainKey: SenderChainKey): void {
        this.structure.senderChainKey = {
            iteration: chainKey.getIteration(),
            seed: u8.encode(chainKey.getSeed())
        }
    }

    getSigningKeyPublic(): Uint8Array {
        return u8.decode(this.structure.senderSigningKey.public)
    }

    getSigningKeyPrivate(): Uint8Array | undefined {
        const privateKey = this.structure.senderSigningKey.private
        return privateKey ? u8.decode(privateKey) : undefined
    }

    hasSenderMessageKey(iteration: number): boolean {
        for (let i = 0; i < this.structure.senderMessageKeys.length; i++) {
            if (this.structure.senderMessageKeys[i]!.iteration === iteration) return true
        }
        return false
    }

    addSenderMessageKey(senderMessageKey: SenderMessageKey): void {
        this.structure.senderMessageKeys.push({
            iteration: senderMessageKey.getIteration(),
            seed: u8.encode(senderMessageKey.getSeed())
        })

        if (this.structure.senderMessageKeys.length > this.MAX_MESSAGE_KEYS) {
            this.structure.senderMessageKeys.shift()
        }
    }

    removeSenderMessageKey(iteration: number): SenderMessageKey | undefined {
        for (let i = 0; i < this.structure.senderMessageKeys.length; i++) {
            const messageKey = this.structure.senderMessageKeys[i]!
            if (messageKey.iteration !== iteration) continue
            this.structure.senderMessageKeys.splice(i, 1)
            return new SenderMessageKey(messageKey.iteration, u8.decode(messageKey.seed))
        }
        return undefined
    }

    getStructure(): SenderKeyStateStructure {
        return this.structure
    }
}

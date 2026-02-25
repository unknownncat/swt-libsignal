import { SenderKeyState, type SenderKeyStateStructure } from './sender-key-state'

export class SenderKeyRecord {
    private readonly MAX_STATES = 5
    private readonly senderKeyStates: SenderKeyState[] = []

    constructor(serialized?: SenderKeyStateStructure[]) {
        if (!serialized) return
        for (let i = 0; i < serialized.length; i++) {
            this.senderKeyStates.push(new SenderKeyState(undefined, undefined, undefined, undefined, undefined, undefined, serialized[i]!))
        }
    }

    isEmpty(): boolean {
        return this.senderKeyStates.length === 0
    }

    getSenderKeyState(keyId?: number): SenderKeyState | undefined {
        if (keyId === undefined) {
            return this.senderKeyStates[this.senderKeyStates.length - 1]
        }

        for (let i = 0; i < this.senderKeyStates.length; i++) {
            const state = this.senderKeyStates[i]!
            if (state.getKeyId() === keyId) return state
        }
        return undefined
    }

    addSenderKeyState(id: number, iteration: number, chainKey: Uint8Array, signatureKey: Uint8Array): void {
        this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, undefined, signatureKey))
        if (this.senderKeyStates.length > this.MAX_STATES) {
            this.senderKeyStates.shift()
        }
    }

    setSenderKeyState(
        id: number,
        iteration: number,
        chainKey: Uint8Array,
        keyPair: { public: Uint8Array; private: Uint8Array }
    ): void {
        this.senderKeyStates.length = 0
        this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, keyPair))
    }

    serialize(): SenderKeyStateStructure[] {
        const out: SenderKeyStateStructure[] = []
        for (let i = 0; i < this.senderKeyStates.length; i++) {
            out.push(this.senderKeyStates[i]!.getStructure())
        }
        return out
    }

    serializeToBytes(): Uint8Array {
        return new Uint8Array(Buffer.from(JSON.stringify(this.serialize()), 'utf8'))
    }

    static deserialize(data: Uint8Array): SenderKeyRecord {
        const text = Buffer.from(data).toString('utf8')
        const parsed = JSON.parse(text) as SenderKeyStateStructure[]
        return new SenderKeyRecord(parsed)
    }
}

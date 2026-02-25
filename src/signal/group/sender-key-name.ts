export interface SenderAddress {
    readonly id: string
    readonly deviceId: number
    toString(): string
}

function intValue(num: number): number {
    const MAX_VALUE = 0x7fffffff
    const MIN_VALUE = -0x80000000
    if (num > MAX_VALUE || num < MIN_VALUE) {
        return num & 0xffffffff
    }
    return num
}

function hashCode(str: string): number {
    let hash = 0
    for (let i = 0; i < str.length; i++) {
        hash = intValue((hash * 31) + str.charCodeAt(i))
    }
    return hash
}

export class SenderKeyName {
    private readonly groupId: string
    private readonly sender: SenderAddress

    constructor(groupId: string, sender: SenderAddress) {
        this.groupId = groupId
        this.sender = sender
    }

    getGroupId(): string {
        return this.groupId
    }

    getSender(): SenderAddress {
        return this.sender
    }

    serialize(): string {
        return `${this.groupId}::${this.sender.id}::${this.sender.deviceId}`
    }

    toString(): string {
        return this.serialize()
    }

    equals(other: SenderKeyName | null): boolean {
        if (other === null) return false
        return this.groupId === other.groupId && this.sender.toString() === other.sender.toString()
    }

    hashCode(): number {
        return hashCode(this.groupId) ^ hashCode(this.sender.toString())
    }
}

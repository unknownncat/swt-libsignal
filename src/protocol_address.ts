export class ProtocolAddress {
    public readonly id: string
    public readonly deviceId: number
    private cachedString: string | null = null

    // Factory

    static from(encodedAddress: string): ProtocolAddress {
        if (typeof encodedAddress !== 'string') {
            throw new TypeError('encodedAddress must be a string')
        }

        const separatorIndex = encodedAddress.lastIndexOf('.')

        if (separatorIndex <= 0 || separatorIndex === encodedAddress.length - 1) {
            throw new Error('Invalid address encoding')
        }

        const id = encodedAddress.slice(0, separatorIndex)
        const deviceStr = encodedAddress.slice(separatorIndex + 1)

        if (!/^\d+$/.test(deviceStr)) {
            throw new Error('Invalid deviceId encoding')
        }

        const deviceId = Number(deviceStr)

        if (!Number.isSafeInteger(deviceId) || deviceId < 0) {
            throw new Error('Invalid deviceId value')
        }

        return new ProtocolAddress(id, deviceId)
    }

    constructor(id: string, deviceId: number) {
        if (typeof id !== 'string' || id.length === 0) {
            throw new TypeError('id must be a non-empty string')
        }

        if (id.includes('.')) {
            throw new TypeError('id must not contain "."')
        }

        if (!Number.isSafeInteger(deviceId) || deviceId < 0) {
            throw new TypeError('deviceId must be a non-negative safe integer')
        }

        this.id = id
        this.deviceId = deviceId
    }

    // Serialization

    toString(): string {
        if (this.cachedString === null) {
            this.cachedString = `${this.id}.${this.deviceId}`
        }
        return this.cachedString
    }

    /* ============================================================
       Equality
    ============================================================ */

    equals(other: unknown): boolean {
        if (!(other instanceof ProtocolAddress)) {
            return false
        }

        return (
            this.id === other.id &&
            this.deviceId === other.deviceId
        )
    }
}

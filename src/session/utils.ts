export function assertUint8(value: unknown): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array)) {
        const name = (value !== null && typeof value === 'object' && 'constructor' in value)
            ? (value.constructor as { name?: string }).name ?? 'Object'
            : typeof value
        throw new TypeError(`Expected Uint8Array instead of: ${name}`)
    }
}

export function toBase64(u: Uint8Array): string {
    return Buffer.from(u).toString('base64')
}

export function fromBase64(b64: string): Uint8Array {
    return new Uint8Array(Buffer.from(b64, 'base64'))
}

export const u8 = {
    encode: (u: Uint8Array | undefined): string | undefined => u ? toBase64(u) : undefined,
    decode: (s: string | undefined): Uint8Array | undefined => s ? fromBase64(s) : undefined,
} as const

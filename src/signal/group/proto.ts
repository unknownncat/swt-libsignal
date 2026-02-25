interface DecodeTarget {
    [key: string]: number | Uint8Array | undefined
}

function varintSize(value: number): number {
    let size = 1
    let current = value >>> 0
    while (current > 0x7f) {
        size += 1
        current >>>= 7
    }
    return size
}

function writeVarint(out: Uint8Array, offset: number, value: number): number {
    let current = value >>> 0
    while (current > 0x7f) {
        out[offset++] = (current & 0x7f) | 0x80
        current >>>= 7
    }
    out[offset++] = current
    return offset
}

function readVarint(input: Uint8Array, offset: number): readonly [number, number] {
    let value = 0
    let shift = 0
    let index = offset

    while (index < input.length) {
        const byte = input[index]!
        value |= (byte & 0x7f) << shift
        index += 1
        if ((byte & 0x80) === 0) {
            return [value >>> 0, index] as const
        }
        shift += 7
    }

    throw new Error('Malformed varint')
}

function skipUnknown(type: number, input: Uint8Array, offset: number): number {
    if (type === 0) {
        const [, next] = readVarint(input, offset)
        return next
    }
    if (type === 2) {
        const [length, next] = readVarint(input, offset)
        return next + length
    }
    throw new Error(`Unsupported wire type: ${type}`)
}

function encodeFields(
    message: DecodeTarget,
    bytesFields: readonly (readonly [number, string])[],
    varintFields: readonly (readonly [number, string])[]
): Uint8Array {
    let size = 0

    for (let i = 0; i < bytesFields.length; i++) {
        const [tag, key] = bytesFields[i]!
        const value = message[key]
        if (!(value instanceof Uint8Array)) continue
        size += varintSize((tag << 3) | 2) + varintSize(value.length) + value.length
    }

    for (let i = 0; i < varintFields.length; i++) {
        const [tag, key] = varintFields[i]!
        const value = message[key]
        if (typeof value !== 'number') continue
        size += varintSize((tag << 3) | 0) + varintSize(value >>> 0)
    }

    const out = new Uint8Array(size)
    let offset = 0

    for (let i = 0; i < bytesFields.length; i++) {
        const [tag, key] = bytesFields[i]!
        const value = message[key]
        if (!(value instanceof Uint8Array)) continue
        offset = writeVarint(out, offset, (tag << 3) | 2)
        offset = writeVarint(out, offset, value.length)
        out.set(value, offset)
        offset += value.length
    }

    for (let i = 0; i < varintFields.length; i++) {
        const [tag, key] = varintFields[i]!
        const value = message[key]
        if (typeof value !== 'number') continue
        offset = writeVarint(out, offset, (tag << 3) | 0)
        offset = writeVarint(out, offset, value >>> 0)
    }

    return out
}

function decodeMessage<T>(
    input: Uint8Array,
    bytesMap: Readonly<Record<number, keyof T>>,
    varintMap: Readonly<Record<number, keyof T>>
): T {
    const target: DecodeTarget = {}
    let offset = 0

    while (offset < input.length) {
        const [header, afterHeader] = readVarint(input, offset)
        offset = afterHeader

        const tag = header >>> 3
        const wireType = header & 0x7

        const bytesField = bytesMap[tag]
        if (wireType === 2 && bytesField) {
            const [length, next] = readVarint(input, offset)
            const end = next + length
            target[bytesField as string] = input.subarray(next, end)
            offset = end
            continue
        }

        const varintField = varintMap[tag]
        if (wireType === 0 && varintField) {
            const [value, next] = readVarint(input, offset)
            target[varintField as string] = value
            offset = next
            continue
        }

        offset = skipUnknown(wireType, input, offset)
    }

    return target as T
}

export interface SenderKeyMessageProto {
    readonly id?: number
    readonly iteration?: number
    readonly ciphertext?: Uint8Array
}

export interface SenderKeyDistributionMessageProto {
    readonly id?: number
    readonly iteration?: number
    readonly chainKey?: Uint8Array
    readonly signingKey?: Uint8Array
}

export const SenderKeyMessageCodec = {
    encode(message: SenderKeyMessageProto): Uint8Array {
        return encodeFields(
            message as DecodeTarget,
            [[3, 'ciphertext']] as const,
            [[1, 'id'], [2, 'iteration']] as const
        )
    },
    decode(input: Uint8Array): SenderKeyMessageProto {
        return decodeMessage<SenderKeyMessageProto>(
            input,
            { 3: 'ciphertext' },
            { 1: 'id', 2: 'iteration' }
        )
    }
} as const

export const SenderKeyDistributionMessageCodec = {
    encode(message: SenderKeyDistributionMessageProto): Uint8Array {
        return encodeFields(
            message as DecodeTarget,
            [[3, 'chainKey'], [4, 'signingKey']] as const,
            [[1, 'id'], [2, 'iteration']] as const
        )
    },
    decode(input: Uint8Array): SenderKeyDistributionMessageProto {
        return decodeMessage<SenderKeyDistributionMessageProto>(
            input,
            { 3: 'chainKey', 4: 'signingKey' },
            { 1: 'id', 2: 'iteration' }
        )
    }
} as const

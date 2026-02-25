import { crypto } from './crypto'

// Constants

const VERSION = 0


// Utils (zero-copy friendly)

function numberToUint16BE(num: number): Uint8Array {
    const out = new Uint8Array(2)
    out[0] = num >> 8 // Shift right by 8 bits to get the high byte
    out[1] = num & 0xff // 0xff is 255, to get the last 8 bits
    return out
}

/* c8 ignore start */
function concatBytes(...arrays: (Uint8Array | null | undefined)[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + (a?.length ?? 0), 0)
    const result = new Uint8Array(total)

    let offset = 0
    for (const arr of arrays) {
        if (arr) {
            result.set(arr, offset)
            offset += arr.length
        }
    }

  return result
}
/* c8 ignore end */

function stringToUtf8(str: string): Uint8Array {
    return new TextEncoder().encode(str)
}

// Iterated Hash (stack-safe)

function iterateHash(
    data: Uint8Array,
    key: Uint8Array,
    count: number
): Uint8Array {

    let result = data

    for (let i = 0; i < count; i++) {
        result = crypto.sha512(
            concatBytes(result, key)
        )
    }

    return result
}

// Display Encoding

function getEncodedChunk(
    hash: Uint8Array,
    offset: number
): string {

    if (hash.length < offset + 5) {
        throw new Error('Hash output too small')
    }

    const chunk =
        (
            hash[offset]! * 2 ** 32 +
            hash[offset + 1]! * 2 ** 24 +
            hash[offset + 2]! * 2 ** 16 +
            hash[offset + 3]! * 2 ** 8 +
            hash[offset + 4]!
        ) % 100000

    // Pad with leading zeros to ensure it's always 5 digits
    return chunk.toString().padStart(5, '0')
}


function getDisplayStringFor(
    identifier: string,
    key: Uint8Array,
    iterations: number
): string {

    const versionBytes = numberToUint16BE(VERSION)

    const combined = concatBytes(
        versionBytes,
        key,
        stringToUtf8(identifier)
    )

    const output = iterateHash(
        combined,
        key,
        iterations
    )

    return (
        getEncodedChunk(output, 0) +
        getEncodedChunk(output, 5) +
        getEncodedChunk(output, 10) +
        getEncodedChunk(output, 15) +
        getEncodedChunk(output, 20) +
        getEncodedChunk(output, 25)
    )
}

// Types

export class FingerprintGenerator {

    private readonly iterations: number

    constructor(iterations: number) {
        if (!Number.isInteger(iterations) || iterations <= 0) {
            throw new Error('iterations must be a positive integer')
        }
        this.iterations = iterations
    }

    createFor(
        localIdentifier: string,
        localIdentityKey: Uint8Array,
        remoteIdentifier: string,
        remoteIdentityKey: Uint8Array
    ): string {

        if (
            typeof localIdentifier !== 'string' ||
            typeof remoteIdentifier !== 'string'
        ) {
            throw new Error('Identifiers must be strings')
        }

        if (
            !(localIdentityKey instanceof Uint8Array) ||
            !(remoteIdentityKey instanceof Uint8Array)
        ) {
            throw new Error('Identity keys must be Uint8Array')
        }

        if (localIdentityKey.length !== 32) {
            throw new Error('Identity key must be 32 bytes (Ed25519/X25519)');
        }

        const localFp = getDisplayStringFor(
            localIdentifier,
            localIdentityKey,
            this.iterations
        )

        const remoteFp = getDisplayStringFor(
            remoteIdentifier,
            remoteIdentityKey,
            this.iterations
        )

        return [localFp, remoteFp]
            .sort()
            .join('')
    }
}

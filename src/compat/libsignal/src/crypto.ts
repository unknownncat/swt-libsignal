import { createCipheriv, createDecipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto'

function assertBuffer(value: unknown, label: string): Buffer {
    if (!Buffer.isBuffer(value)) {
        const ctor = (value as { constructor?: { name?: string } } | null | undefined)?.constructor?.name ?? typeof value
        throw new TypeError(`Expected Buffer for ${label}, got: ${ctor}`)
    }
    return value
}

export function encrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    const safeKey = assertBuffer(key, 'key')
    const safeData = assertBuffer(data, 'data')
    const safeIv = assertBuffer(iv, 'iv')
    const cipher = createCipheriv('aes-256-cbc', safeKey, safeIv)
    return Buffer.concat([cipher.update(safeData), cipher.final()])
}

export function decrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    const safeKey = assertBuffer(key, 'key')
    const safeData = assertBuffer(data, 'data')
    const safeIv = assertBuffer(iv, 'iv')
    const decipher = createDecipheriv('aes-256-cbc', safeKey, safeIv)
    return Buffer.concat([decipher.update(safeData), decipher.final()])
}

export function calculateMAC(key: Buffer, data: Buffer): Buffer {
    const safeKey = assertBuffer(key, 'key')
    const safeData = assertBuffer(data, 'data')
    return createHmac('sha256', safeKey).update(safeData).digest()
}

export function hash(data: Buffer): Buffer {
    const safeData = assertBuffer(data, 'data')
    return createHash('sha512').update(safeData).digest()
}

export function deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks = 3): Buffer[] {
    const safeInput = assertBuffer(input, 'input')
    const safeSalt = assertBuffer(salt, 'salt')
    const safeInfo = assertBuffer(info, 'info')

    if (safeSalt.byteLength !== 32) {
        throw new Error('Got salt of incorrect length')
    }
    if (!Number.isInteger(chunks) || chunks < 1 || chunks > 3) {
        throw new RangeError('chunks must be an integer between 1 and 3')
    }

    const prk = calculateMAC(safeSalt, safeInput)
    const infoArray = new Uint8Array(safeInfo.byteLength + 1 + 32)
    infoArray.set(safeInfo, 32)
    infoArray[infoArray.length - 1] = 1

    const signed: Buffer[] = [calculateMAC(prk, Buffer.from(infoArray.slice(32)))]
    if (chunks > 1) {
        infoArray.set(signed[signed.length - 1]!)
        infoArray[infoArray.length - 1] = 2
        signed.push(calculateMAC(prk, Buffer.from(infoArray)))
    }
    if (chunks > 2) {
        infoArray.set(signed[signed.length - 1]!)
        infoArray[infoArray.length - 1] = 3
        signed.push(calculateMAC(prk, Buffer.from(infoArray)))
    }
    return signed
}

export function verifyMAC(data: Buffer, key: Buffer, mac: Buffer, length: number): void {
    const safeData = assertBuffer(data, 'data')
    const safeKey = assertBuffer(key, 'key')
    const safeMac = assertBuffer(mac, 'mac')

    const calculated = calculateMAC(safeKey, safeData).subarray(0, length)
    if (safeMac.length !== length || calculated.length !== length) {
        throw new Error('Bad MAC length')
    }
    if (!timingSafeEqual(safeMac, calculated)) {
        throw new Error('Bad MAC')
    }
}


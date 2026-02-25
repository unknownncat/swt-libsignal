export type Brand<T, B extends string> = T & { readonly __brand: B }

export type Ed25519PublicKey = Brand<Uint8Array, 'Ed25519PublicKey'>
export type Ed25519SecretKey = Brand<Uint8Array, 'Ed25519SecretKey'>
export type X25519PublicKey = Brand<Uint8Array, 'X25519PublicKey'>
export type X25519SecretKey = Brand<Uint8Array, 'X25519SecretKey'>
export type AesKey32 = Brand<Uint8Array, 'AesKey32'>
export type MacKey32 = Brand<Uint8Array, 'MacKey32'>

function asFixedLength<T extends string>(value: Uint8Array, expected: number, label: string, brand: T): Brand<Uint8Array, T> {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`${label} must be Uint8Array`)
    }
    if (value.length !== expected) {
        throw new TypeError(`${label} must be ${expected} bytes`)
    }
    return value as Brand<Uint8Array, T>
}

export function asEd25519PublicKey(value: Uint8Array): Ed25519PublicKey {
    return asFixedLength(value, 32, 'Ed25519 public key', 'Ed25519PublicKey')
}

export function asEd25519SecretKey(value: Uint8Array): Ed25519SecretKey {
    return asFixedLength(value, 64, 'Ed25519 private key', 'Ed25519SecretKey')
}

export function asX25519PublicKey(value: Uint8Array): X25519PublicKey {
    return asFixedLength(value, 32, 'X25519 public key', 'X25519PublicKey')
}

export function asX25519SecretKey(value: Uint8Array): X25519SecretKey {
    return asFixedLength(value, 32, 'X25519 secret key', 'X25519SecretKey')
}

export function asAesKey32(value: Uint8Array): AesKey32 {
    return asFixedLength(value, 32, 'AES-256 key', 'AesKey32')
}

export function asMacKey32(value: Uint8Array): MacKey32 {
    return asFixedLength(value, 32, 'MAC key', 'MacKey32')
}

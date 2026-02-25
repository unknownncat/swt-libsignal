import { secureZero } from '../../utils'
import type {
    BaseStorageAdapter,
    BatchDeleteEntry,
    BatchGetOptions,
    BatchSetEntry
} from './types'

export interface InMemoryStorageOptions {
    readonly mutability?: 'isolated' | 'shared'
}

function cloneValue<T>(value: T): T {
    if (value instanceof Uint8Array) return value.slice() as T
    return value
}

export class InMemoryStorage<TValue = Uint8Array> implements BaseStorageAdapter<TValue> {
    private readonly store = new Map<string, TValue>()
    private readonly mutability: 'isolated' | 'shared'
    readonly name = 'in-memory'

    constructor(initial?: Readonly<Record<string, TValue>>, options: InMemoryStorageOptions = {}) {
        this.mutability = options.mutability ?? 'isolated'
        if (initial) {
            for (const [k, v] of Object.entries(initial)) {
                this.store.set(k, this.mutability === 'isolated' ? cloneValue(v) : v)
            }
        }
    }

    get(key: string): TValue | undefined {
        const value = this.store.get(key)
        if (value === undefined) return undefined
        return this.mutability === 'isolated' ? cloneValue(value) : value
    }

    set(key: string, value: TValue): void {
        this.store.set(key, this.mutability === 'isolated' ? cloneValue(value) : value)
    }

    delete(key: string): void {
        this.store.delete(key)
    }

    getMany(keys: readonly string[], _options?: BatchGetOptions): readonly (TValue | undefined)[] {
        const out = new Array<TValue | undefined>(keys.length)
        for (let i = 0; i < keys.length; i++) {
            out[i] = this.get(keys[i]!)
        }
        return out
    }

    setMany(entries: readonly BatchSetEntry<TValue>[]): void {
        for (let i = 0; i < entries.length; i++) {
            this.set(entries[i]!.key, entries[i]!.value)
        }
    }

    deleteMany(entries: readonly BatchDeleteEntry[]): void {
        for (let i = 0; i < entries.length; i++) {
            this.store.delete(entries[i]!.key)
        }
    }

    zeroize(key: string): void {
        const value = this.store.get(key)
        if (value instanceof Uint8Array) secureZero(value)   // ← secureZero
    }

    clear(options?: { readonly secure?: boolean }): void {
        if (options?.secure) {
            for (const value of this.store.values()) {
                if (value instanceof Uint8Array) secureZero(value)   // ← secureZero
            }
        }
        this.store.clear()
    }

    close(): void { }
}

export function createInMemoryStorage<TValue = Uint8Array>(
    initial?: Readonly<Record<string, TValue>>,
    options?: InMemoryStorageOptions
) {
    return new InMemoryStorage(initial, options)
}
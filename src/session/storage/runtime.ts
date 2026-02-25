import type {
    BatchDeleteEntry,
    BatchGetOptions,
    BatchSetEntry,
    MaybePromise,
    StorageAdapter
} from './types'

function isPromiseLike<T>(value: MaybePromise<T>): value is Promise<T> {
    return typeof (value as Promise<T> | undefined)?.then === 'function'
}

export function getValue<TValue>(adapter: StorageAdapter<TValue>, key: string): MaybePromise<TValue | undefined> {
    return adapter.get(key)
}

export function setValue<TValue>(adapter: StorageAdapter<TValue>, key: string, value: TValue): MaybePromise<void> {
    return adapter.set(key, value)
}

export function deleteValue<TValue>(adapter: StorageAdapter<TValue>, key: string): MaybePromise<void> {
    return adapter.delete(key)
}

export function getMany<TValue>(adapter: StorageAdapter<TValue>, keys: readonly string[], options?: BatchGetOptions): MaybePromise<readonly (TValue | undefined)[]> {
    if (adapter.getMany) return adapter.getMany(keys, options)
    const out = new Array<TValue | undefined>(keys.length)
    for (let i = 0; i < keys.length; i++) {
        const value = adapter.get(keys[i]!)
        if (isPromiseLike(value)) {
            return Promise.all(keys.map((key) => Promise.resolve(adapter.get(key))))
        }
        out[i] = value
    }
    return out
}

export function setMany<TValue>(adapter: StorageAdapter<TValue>, entries: readonly BatchSetEntry<TValue>[]): MaybePromise<void> {
    if (adapter.setMany) return adapter.setMany(entries)
    for (let i = 0; i < entries.length; i++) {
        const r = adapter.set(entries[i]!.key, entries[i]!.value)
        if (isPromiseLike(r)) {
            return Promise.all(entries.map((e) => Promise.resolve(adapter.set(e.key, e.value)))).then(() => undefined)
        }
    }
}

export function deleteMany<TValue>(adapter: StorageAdapter<TValue>, entries: readonly BatchDeleteEntry[]): MaybePromise<void> {
    if (adapter.deleteMany) return adapter.deleteMany(entries)
    for (let i = 0; i < entries.length; i++) {
        const r = adapter.delete(entries[i]!.key)
        if (isPromiseLike(r)) {
            return Promise.all(entries.map((e) => Promise.resolve(adapter.delete(e.key)))).then(() => undefined)
        }
    }
}

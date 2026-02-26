export * from './types'
export * from './runtime'
export * from './in-memory'
export * from './migrations'
export * from './adapter'
export * from './atomic-json-file'
export * from './sqlite-async'

import type {
    BatchDeleteEntry,
    BatchGetOptions,
    BatchSetEntry,
    MaybePromise,
    StorageAdapter
} from './types'
import { deleteMany, deleteValue, getMany, getValue, setMany, setValue } from './runtime'

export class StorageManager<TValue = Uint8Array> {
    constructor(public readonly adapter: StorageAdapter<TValue>) { }

    get(key: string): MaybePromise<TValue | undefined> {
        return getValue(this.adapter, key)
    }

    set(key: string, value: TValue): MaybePromise<void> {
        return setValue(this.adapter, key, value)
    }

    delete(key: string): MaybePromise<void> {
        return deleteValue(this.adapter, key)
    }

    getMany(keys: readonly string[], options?: BatchGetOptions): MaybePromise<readonly (TValue | undefined)[]> {
        return getMany(this.adapter, keys, options)
    }

    setMany(entries: readonly BatchSetEntry<TValue>[]): MaybePromise<void> {
        return setMany(this.adapter, entries)
    }

    deleteMany(entries: readonly BatchDeleteEntry[]): MaybePromise<void> {
        return deleteMany(this.adapter, entries)
    }

    close(): MaybePromise<void> {
        return this.adapter.close?.()
    }
}

export function createStorageManager<TValue = Uint8Array>(adapter: StorageAdapter<TValue>) {
    return new StorageManager(adapter)
}

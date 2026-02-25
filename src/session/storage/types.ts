export type MaybePromise<T> = T | Promise<T>

export interface BatchGetOptions {
    readonly prefetch?: boolean
    readonly cacheHint?: 'none' | 'hot' | 'ephemeral'
}

export interface BatchSetEntry<TValue = Uint8Array> {
    readonly key: string
    readonly value: TValue
}

export interface BatchDeleteEntry {
    readonly key: string
}

export type BatchOperation<TValue = Uint8Array> =
    | { readonly type: 'set'; readonly key: string; readonly value: TValue }
    | { readonly type: 'delete'; readonly key: string }

export interface SecureStorageControls {
    /**
     * Zeroiza buffers sensíveis armazenados internamente para reduzir remanência em memória.
     */
    zeroize?(key: string): MaybePromise<void>
    /**
     * Remove e opcionalmente zeroiza todas as entradas.
     */
    clear?(options?: { readonly secure?: boolean }): MaybePromise<void>
    close?(): MaybePromise<void>
}

/**
 * Contrato mínimo e síncrono para caminhos quentes com menor overhead possível.
 */
export interface BaseStorageAdapter<TValue = Uint8Array> extends SecureStorageControls {
    readonly name?: string
    get(key: string): TValue | undefined
    set(key: string, value: TValue): void
    delete(key: string): void
    getMany?(keys: readonly string[], options?: BatchGetOptions): readonly (TValue | undefined)[]
    setMany?(entries: readonly BatchSetEntry<TValue>[]): void
    deleteMany?(entries: readonly BatchDeleteEntry[]): void
    prefetch?(keys: readonly string[]): void
    cacheHint?(key: string, hint: NonNullable<BatchGetOptions['cacheHint']>): void
}

/**
 * Extensão opcional para adaptadores com transações explícitas.
 */
export interface TransactionalStorageAdapter<TValue = Uint8Array> {
    transaction<T>(run: (tx: BaseStorageAdapter<TValue>) => MaybePromise<T>): MaybePromise<T>
}

/**
 * Contrato assíncrono opcional para backends I/O-bound.
 */
export interface AsyncStorageAdapter<TValue = Uint8Array> extends SecureStorageControls {
    readonly name?: string
    get(key: string): Promise<TValue | undefined>
    set(key: string, value: TValue): Promise<void>
    delete(key: string): Promise<void>
    getMany?(keys: readonly string[], options?: BatchGetOptions): Promise<readonly (TValue | undefined)[]>
    setMany?(entries: readonly BatchSetEntry<TValue>[]): Promise<void>
    deleteMany?(entries: readonly BatchDeleteEntry[]): Promise<void>
    prefetch?(keys: readonly string[]): Promise<void>
    cacheHint?(key: string, hint: NonNullable<BatchGetOptions['cacheHint']>): Promise<void>
    migrate?(fromVersion: number, toVersion: number): Promise<void>
}

export type StorageAdapter<TValue = Uint8Array> = BaseStorageAdapter<TValue> | AsyncStorageAdapter<TValue>


export interface SessionStorageAtomicOps {
    storeSessionAndRemovePreKey?(addressName: string, sessionRecord: unknown, preKeyId: number): MaybePromise<void>
}

export interface StorageManagerOptions<TValue = Uint8Array> {
    readonly adapter: StorageAdapter<TValue>
}

export type BatchOp = BatchOperation<unknown>

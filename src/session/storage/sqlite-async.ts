import type {
    AsyncStorageAdapter,
    BaseStorageAdapter,
    BatchDeleteEntry,
    BatchGetOptions,
    BatchSetEntry,
    MaybePromise,
    TransactionalStorageAdapter
} from './types'

type SQLiteStatement = {
    run(...params: unknown[]): unknown
    get(...params: unknown[]): unknown
    all?(...params: unknown[]): unknown[]
}

type SQLiteDatabaseSync = {
    exec(sql: string): void
    prepare(sql: string): SQLiteStatement
    close(): void
}

type SQLiteModule = {
    DatabaseSync: new (path: string) => SQLiteDatabaseSync
}

const NODE_SQLITE_SPECIFIER = 'node:sqlite'
const U8_TAG = '__swt_u8'

export interface SqliteAsyncStorageCodec<TValue = unknown> {
    encode(value: TValue): Uint8Array
    decode(bytes: Uint8Array): TValue
}

export interface SqliteAsyncStorageOptions<TValue = unknown> {
    readonly walMode?: 'WAL' | 'DELETE'
    readonly synchronous?: 'FULL' | 'NORMAL' | 'OFF'
    readonly busyTimeoutMs?: number
    readonly secureDelete?: boolean
    readonly checkpointOnClose?: boolean
    readonly codec?: SqliteAsyncStorageCodec<TValue>
}

function toBufferView(data: Uint8Array): Buffer {
    return Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

function defaultCodec<TValue = unknown>(): SqliteAsyncStorageCodec<TValue> {
    return {
        encode(value: TValue): Uint8Array {
            const json = JSON.stringify(value, (_key, candidate) => {
                if (candidate instanceof Uint8Array) {
                    return { [U8_TAG]: Buffer.from(candidate).toString('base64') }
                }
                return candidate
            })
            return Buffer.from(json, 'utf8')
        },
        decode(bytes: Uint8Array): TValue {
            const decoded = Buffer.from(bytes).toString('utf8')
            return JSON.parse(decoded, (_key, candidate) => {
                if (
                    candidate &&
                    typeof candidate === 'object' &&
                    typeof (candidate as { [U8_TAG]?: unknown })[U8_TAG] === 'string'
                ) {
                    return Uint8Array.from(Buffer.from((candidate as { [U8_TAG]: string })[U8_TAG], 'base64'))
                }
                return candidate
            }) as TValue
        }
    }
}

function zeroizeDecodedValue(value: unknown): unknown {
    if (value instanceof Uint8Array) {
        return new Uint8Array(value.length)
    }
    if (Array.isArray(value)) {
        return value.map((entry) => zeroizeDecodedValue(entry))
    }
    if (!value || typeof value !== 'object') {
        return value
    }

    const out: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(value)) {
        out[key] = zeroizeDecodedValue(entry)
    }
    return out
}

async function loadNodeSqlite(): Promise<SQLiteModule> {
    try {
        const module = await import(NODE_SQLITE_SPECIFIER as string) as Partial<SQLiteModule>
        /* c8 ignore start */
        if (typeof module.DatabaseSync !== 'function') {
            throw new Error('node:sqlite DatabaseSync export is unavailable in this Node runtime')
        }
        /* c8 ignore stop */
        return module as SQLiteModule
        /* v8 ignore start */
    } catch (error) {
        throw new Error(
            'SQLite adapter requires Node.js runtime support for node:sqlite (recommended: Node >= 22).',
            { cause: error instanceof Error ? error : undefined }
        )
        /* v8 ignore stop */
    }
}

export class SqliteAsyncStorageAdapter<TValue = unknown> implements AsyncStorageAdapter<TValue>, TransactionalStorageAdapter<TValue> {
    readonly name = 'sqlite-async'
    private readonly db: SQLiteDatabaseSync
    private readonly codec: SqliteAsyncStorageCodec<TValue>

    private readonly getStmt: SQLiteStatement
    private readonly setStmt: SQLiteStatement
    private readonly deleteStmt: SQLiteStatement
    private readonly zeroizeStmt: SQLiteStatement
    private readonly deleteAllStmt: SQLiteStatement
    private readonly listKeysStmt: SQLiteStatement
    private txDepth = 0
    private txCounter = 0

    private constructor(
        db: SQLiteDatabaseSync,
        options: SqliteAsyncStorageOptions<TValue>
    ) {
        this.db = db
        this.codec = options.codec ?? defaultCodec<TValue>()

        const walMode = options.walMode ?? 'WAL'
        const synchronous = options.synchronous ?? 'FULL'
        const busyTimeoutMs = options.busyTimeoutMs ?? 5000
        const secureDelete = options.secureDelete ?? true

        this.db.exec(`PRAGMA journal_mode=${walMode}`)
        this.db.exec(`PRAGMA synchronous=${synchronous}`)
        this.db.exec(`PRAGMA busy_timeout=${busyTimeoutMs}`)
        this.db.exec(`PRAGMA secure_delete=${secureDelete ? 'ON' : 'OFF'}`)

        this.db.exec(`
            CREATE TABLE IF NOT EXISTS swt_storage (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        `)

        this.getStmt = this.db.prepare('SELECT value FROM swt_storage WHERE key = ?1')
        this.setStmt = this.db.prepare(`
            INSERT INTO swt_storage (key, value) VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        `)
        this.deleteStmt = this.db.prepare('DELETE FROM swt_storage WHERE key = ?1')
        this.zeroizeStmt = this.db.prepare('UPDATE swt_storage SET value = zeroblob(length(value)) WHERE key = ?1')
        this.deleteAllStmt = this.db.prepare('DELETE FROM swt_storage')
        this.listKeysStmt = this.db.prepare('SELECT key FROM swt_storage')
    }

    static async open<TValue = unknown>(
        path: string,
        options: SqliteAsyncStorageOptions<TValue> = {}
    ): Promise<SqliteAsyncStorageAdapter<TValue>> {
        const sqlite = await loadNodeSqlite()
        const db = new sqlite.DatabaseSync(path)
        return new SqliteAsyncStorageAdapter<TValue>(db, options)
    }

    private decodeRow(row: unknown): TValue | undefined {
        if (!row || typeof row !== 'object') return undefined
        const value = (row as { value?: Uint8Array }).value
        if (!(value instanceof Uint8Array)) return undefined
        const safe = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        return this.codec.decode(safe)
    }

    private withTransactionBoundary<T>(run: () => Promise<T>): Promise<T> {
        const savepoint = `swt_sp_${++this.txCounter}`
        const nested = this.txDepth > 0

        if (nested) {
            this.db.exec(`SAVEPOINT ${savepoint}`)
        } else {
            this.db.exec('BEGIN IMMEDIATE')
        }
        this.txDepth += 1

        const finalize = async (action: 'commit' | 'rollback'): Promise<void> => {
            if (nested) {
                this.db.exec(action === 'commit' ? `RELEASE SAVEPOINT ${savepoint}` : `ROLLBACK TO SAVEPOINT ${savepoint}`)
                if (action === 'rollback') {
                    this.db.exec(`RELEASE SAVEPOINT ${savepoint}`)
                }
                return
            }
            this.db.exec(action === 'commit' ? 'COMMIT' : 'ROLLBACK')
        }

        return run()
            .then(async (result) => {
                await finalize('commit')
                return result
            })
            .catch(async (error) => {
                await finalize('rollback')
                throw error
            })
            .finally(() => {
                this.txDepth = Math.max(0, this.txDepth - 1)
            })
    }

    async transaction<T>(run: (tx: BaseStorageAdapter<TValue>) => MaybePromise<T>): Promise<T> {
        return this.withTransactionBoundary(async () => Promise.resolve(run(this as unknown as BaseStorageAdapter<TValue>)))
    }

    async get(key: string): Promise<TValue | undefined> {
        const row = this.getStmt.get(key)
        return this.decodeRow(row)
    }

    async set(key: string, value: TValue): Promise<void> {
        const encoded = this.codec.encode(value)
        this.setStmt.run(key, toBufferView(encoded))
    }

    async delete(key: string): Promise<void> {
        this.deleteStmt.run(key)
    }

    async getMany(keys: readonly string[], _options?: BatchGetOptions): Promise<readonly (TValue | undefined)[]> {
        const out = new Array<TValue | undefined>(keys.length)
        for (let i = 0; i < keys.length; i++) {
            out[i] = await this.get(keys[i]!)
        }
        return out
    }

    async setMany(entries: readonly BatchSetEntry<TValue>[]): Promise<void> {
        await this.transaction(async () => {
            for (let i = 0; i < entries.length; i++) {
                await this.set(entries[i]!.key, entries[i]!.value)
            }
        })
    }

    async deleteMany(entries: readonly BatchDeleteEntry[]): Promise<void> {
        await this.transaction(async () => {
            for (let i = 0; i < entries.length; i++) {
                await this.delete(entries[i]!.key)
            }
        })
    }

    async zeroize(key: string): Promise<void> {
        const row = this.getStmt.get(key)
        if (!row || typeof row !== 'object') {
            return
        }

        const value = (row as { value?: Uint8Array }).value
        if (!(value instanceof Uint8Array)) {
            return
        }

        try {
            const decoded = this.codec.decode(new Uint8Array(value.buffer, value.byteOffset, value.byteLength))
            const zeroized = zeroizeDecodedValue(decoded) as TValue
            const encoded = this.codec.encode(zeroized)
            this.setStmt.run(key, toBufferView(encoded))
        } catch {
            this.zeroizeStmt.run(key)
        }
    }

    async clear(options?: { readonly secure?: boolean }): Promise<void> {
        if (options?.secure) {
            const rows = this.listKeysStmt.all?.() ?? []
            for (let i = 0; i < rows.length; i++) {
                const key = (rows[i] as { key?: unknown }).key
                if (typeof key === 'string') {
                    await this.zeroize(key)
                }
            }
            this.db.exec('UPDATE swt_storage SET value = zeroblob(length(value))')
        }
        this.deleteAllStmt.run()
    }

    async close(): Promise<void> {
        /* v8 ignore start */
        try {
            this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
        } catch {
            // Ignore checkpoint errors for runtimes/backends that do not support WAL.
        }
        /* v8 ignore stop */
        this.db.close()
    }
}

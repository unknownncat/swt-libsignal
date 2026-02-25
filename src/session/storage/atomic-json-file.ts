import { readFile, writeFile, mkdir, rename, open } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { AsyncStorageAdapter, BatchDeleteEntry, BatchGetOptions, BatchSetEntry } from './types'
import { secureZero } from '../../utils'

export interface FileStorageAdapterOptions {
    readonly flushEveryWrites?: number
    readonly fsyncOnFlush?: boolean
}

export class AtomicJsonFileAsyncStorageAdapter implements AsyncStorageAdapter<Uint8Array> {
    readonly name = 'atomic-json-file-async'
    private readonly map = new Map<string, Uint8Array>()
    private readonly path: string
    private readonly flushEveryWrites: number
    private readonly fsyncOnFlush: boolean
    private pendingWrites = 0
    private initialized = false

    constructor(path: string, options: FileStorageAdapterOptions = {}) {
        this.path = path
        this.flushEveryWrites = options.flushEveryWrites ?? 64
        this.fsyncOnFlush = options.fsyncOnFlush ?? false
    }

    private async init(): Promise<void> {
        if (this.initialized) return
        this.initialized = true
        try {
            const raw = await readFile(this.path, 'utf8')
            const parsed = JSON.parse(raw) as Record<string, string>
            for (const [k, v] of Object.entries(parsed)) {
                this.map.set(k, Uint8Array.from(Buffer.from(v, 'base64')))
            }
        } catch {
            // arquivo ainda não existe
        }
    }

    private async atomicWrite(json: string): Promise<void> {
        await mkdir(dirname(this.path), { recursive: true })
        const tempPath = `${this.path}.tmp`
        await writeFile(tempPath, json, 'utf8')

        if (this.fsyncOnFlush) {
            const handle = await open(tempPath, 'r+')
            await handle.sync()
            await handle.close()
        }

        await rename(tempPath, this.path)
    }

    private async flushIfNeeded(force = false): Promise<void> {
        if (!force && this.pendingWrites < this.flushEveryWrites) return
        this.pendingWrites = 0
        const out: Record<string, string> = {}
        for (const [k, v] of this.map.entries()) {
            out[k] = Buffer.from(v).toString('base64')
        }
        await this.atomicWrite(JSON.stringify(out))
    }

    async get(key: string): Promise<Uint8Array | undefined> {
        await this.init()
        const value = this.map.get(key)
        return value?.slice()
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.init()
        this.map.set(key, value.slice())
        this.pendingWrites++
        await this.flushIfNeeded()
    }

    async delete(key: string): Promise<void> {
        await this.init()
        this.map.delete(key)
        this.pendingWrites++
        await this.flushIfNeeded()
    }

    async getMany(keys: readonly string[], _options?: BatchGetOptions): Promise<readonly (Uint8Array | undefined)[]> {
        await this.init()
        const out = new Array<Uint8Array | undefined>(keys.length)
        for (let i = 0; i < keys.length; i++) out[i] = this.map.get(keys[i]!)?.slice()
        return out
    }

    async setMany(entries: readonly BatchSetEntry<Uint8Array>[]): Promise<void> {
        await this.init()
        for (let i = 0; i < entries.length; i++) {
            this.map.set(entries[i]!.key, entries[i]!.value.slice())
        }
        this.pendingWrites += entries.length
        await this.flushIfNeeded()
    }

    async deleteMany(entries: readonly BatchDeleteEntry[]): Promise<void> {
        await this.init()
        for (let i = 0; i < entries.length; i++) this.map.delete(entries[i]!.key)
        this.pendingWrites += entries.length
        await this.flushIfNeeded()
    }

    async zeroize(key: string): Promise<void> {
        await this.init()
        const value = this.map.get(key)
        if (value instanceof Uint8Array) secureZero(value)   // ← secureZero
    }

    async clear(options?: { readonly secure?: boolean }): Promise<void> {
        await this.init()
        if (options?.secure) {
            for (const value of this.map.values()) {
                if (value instanceof Uint8Array) secureZero(value)   // ← secureZero
            }
        }
        this.map.clear()
        this.pendingWrites++
        await this.flushIfNeeded(true)
    }

    async close(): Promise<void> {
        await this.flushIfNeeded(true)
    }
}

export class FileAsyncStorageAdapter extends AtomicJsonFileAsyncStorageAdapter { }
export interface LIDMapping {
    readonly pn: string
    readonly lid: string
}

export interface LIDMappingKeyStore {
    get(keys: readonly string[]): Promise<Record<string, string | undefined>>
    set(values: Record<string, string>): Promise<void>
}

export class LIDMappingStore {
    private readonly pnToLid = new Map<string, string>()
    private readonly lidToPn = new Map<string, string>()
    private readonly keyStore: LIDMappingKeyStore | undefined

    constructor(keyStore?: LIDMappingKeyStore) {
        this.keyStore = keyStore
    }

    async storeLIDPNMappings(pairs: readonly LIDMapping[]): Promise<void> {
        if (pairs.length === 0) return

        const updates: Record<string, string> = {}

        for (let i = 0; i < pairs.length; i++) {
            const pair = pairs[i]!
            if (!pair.pn || !pair.lid) continue

            this.pnToLid.set(pair.pn, pair.lid)
            this.lidToPn.set(pair.lid, pair.pn)
            updates[pair.pn] = pair.lid
            updates[`${pair.lid}_reverse`] = pair.pn
        }

        if (this.keyStore && Object.keys(updates).length > 0) {
            await this.keyStore.set(updates)
        }
    }

    async getLIDForPN(pn: string): Promise<string | null> {
        const value = await this.getLIDsForPNs([pn])
        return value[0]?.lid ?? null
    }

    async getLIDsForPNs(pns: readonly string[]): Promise<readonly LIDMapping[]> {
        const unique = Array.from(new Set(pns.filter((value) => value.length > 0)))
        if (unique.length === 0) return []

        const out: LIDMapping[] = []
        const misses: string[] = []

        for (let i = 0; i < unique.length; i++) {
            const pn = unique[i]!
            const cached = this.pnToLid.get(pn)
            if (cached) {
                out.push({ pn, lid: cached })
            } else {
                misses.push(pn)
            }
        }

        if (this.keyStore && misses.length > 0) {
            const stored = await this.keyStore.get(misses)
            for (let i = 0; i < misses.length; i++) {
                const pn = misses[i]!
                const lid = stored[pn]
                if (!lid) continue
                this.pnToLid.set(pn, lid)
                this.lidToPn.set(lid, pn)
                out.push({ pn, lid })
            }
        }

        return out
    }

    async getPNForLID(lid: string): Promise<string | null> {
        const value = await this.getPNsForLIDs([lid])
        return value[0]?.pn ?? null
    }

    async getPNsForLIDs(lids: readonly string[]): Promise<readonly LIDMapping[]> {
        const unique = Array.from(new Set(lids.filter((value) => value.length > 0)))
        if (unique.length === 0) return []

        const out: LIDMapping[] = []
        const misses: string[] = []

        for (let i = 0; i < unique.length; i++) {
            const lid = unique[i]!
            const cached = this.lidToPn.get(lid)
            if (cached) {
                out.push({ lid, pn: cached })
            } else {
                misses.push(lid)
            }
        }

        if (this.keyStore && misses.length > 0) {
            const reverseKeys = misses.map((lid) => `${lid}_reverse`)
            const stored = await this.keyStore.get(reverseKeys)
            for (let i = 0; i < misses.length; i++) {
                const lid = misses[i]!
                const pn = stored[`${lid}_reverse`]
                if (!pn) continue
                this.lidToPn.set(lid, pn)
                this.pnToLid.set(pn, lid)
                out.push({ lid, pn })
            }
        }

        return out
    }
}

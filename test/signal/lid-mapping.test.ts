import { describe, expect, it } from 'vitest'
import { LIDMappingStore } from '../../src/signal/lid-mapping'

describe('lid mapping store', () => {
  it('stores and resolves mappings in both directions', async () => {
    const db = new Map<string, string>()
    const store = new LIDMappingStore({
      async get(keys) {
        const out: Record<string, string | undefined> = {}
        for (let i = 0; i < keys.length; i++) {
          out[keys[i]!] = db.get(keys[i]!)
        }
        return out
      },
      async set(values) {
        for (const [key, value] of Object.entries(values)) {
          db.set(key, value)
        }
      }
    })

    await store.storeLIDPNMappings([
      { pn: '5511912345678@s.whatsapp.net', lid: '123456@lid' },
      { pn: '5511987654321@s.whatsapp.net', lid: '654321@lid' },
    ])

    await expect(store.getLIDForPN('5511912345678@s.whatsapp.net')).resolves.toBe('123456@lid')
    await expect(store.getPNForLID('654321@lid')).resolves.toBe('5511987654321@s.whatsapp.net')

    const batch = await store.getLIDsForPNs([
      '5511912345678@s.whatsapp.net',
      '5511987654321@s.whatsapp.net',
      'missing@s.whatsapp.net',
    ])
    expect(batch).toEqual([
      { pn: '5511912345678@s.whatsapp.net', lid: '123456@lid' },
      { pn: '5511987654321@s.whatsapp.net', lid: '654321@lid' },
    ])
  })
})

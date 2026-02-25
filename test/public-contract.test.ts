import { describe, expect, it } from 'vitest'
import * as api from '../src/public/index'

describe('public contract', () => {
  it('exports key stable APIs', () => {
    expect(api.ProtocolAddress).toBeTypeOf('function')
    expect(api.SessionRecord).toBeTypeOf('function')
    expect(api.SessionEntry).toBeTypeOf('function')
    expect(api.crypto).toBeDefined()
    expect(api.cryptoAsync).toBeDefined()
    expect(api.enqueue).toBeTypeOf('function')
    expect(api.createSignalAsync).toBeTypeOf('function')
  })

  it('ProtocolAddress encodes/decodes and compares values', () => {
    const a = new api.ProtocolAddress('alice', 1)
    const b = api.ProtocolAddress.from('alice.1')
    const c = new api.ProtocolAddress('alice', 2)

    expect(a.toString()).toBe('alice.1')
    expect(a.equals(b)).toBe(true)
    expect(a.equals(c)).toBe(false)
    expect(() => api.ProtocolAddress.from('alice')).toThrow('Invalid address encoding')
  })
})

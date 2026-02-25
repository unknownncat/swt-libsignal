import { describe, expect, it, vi } from 'vitest'
import { SessionBuilder } from '../../src/session/builder/session-builder'
import { ProtocolAddress } from '../../src/protocol_address'
import { signalCrypto } from '../../src/curve'

describe('SessionBuilder X3DH compat mode', () => {
  const storage = {
    isTrustedIdentity: async () => true,
    loadSession: async () => undefined,
    storeSession: async () => undefined,
    getOurIdentity: async () => ({ pubKey: new Uint8Array(32), privKey: new Uint8Array(64) }),
    loadPreKey: async () => undefined,
    loadSignedPreKey: async () => undefined,
  }

  it('strict mode fails when Ed25519->X25519 conversion fails', () => {
    const builder = new SessionBuilder(storage, new ProtocolAddress('peer', 1), { compatMode: 'strict' })
    const convertSpy = vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519').mockImplementation(() => {
      throw new Error('conversion failed')
    })

    try {
      expect(() => (builder as unknown as { resolveTheirIdentityDhPublicKey: Function }).resolveTheirIdentityDhPublicKey(new Uint8Array(32).fill(9)))
        .toThrow('X3DH strict mode rejected remote identity key conversion')
    } finally {
      convertSpy.mockRestore()
    }
  })

  it('legacy mode keeps fallback and warns only once', () => {
    const warn = vi.fn()
    const builder = new SessionBuilder(storage, new ProtocolAddress('peer', 1), { compatMode: 'legacy', warn })
    const convertSpy = vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519').mockImplementation(() => {
      throw new Error('conversion failed')
    })
    const rawIdentity = new Uint8Array(32).fill(7)

    try {
      const first = (builder as unknown as { resolveTheirIdentityDhPublicKey: Function }).resolveTheirIdentityDhPublicKey(rawIdentity)
      const second = (builder as unknown as { resolveTheirIdentityDhPublicKey: Function }).resolveTheirIdentityDhPublicKey(rawIdentity)

      expect(first).toBe(rawIdentity)
      expect(second).toBe(rawIdentity)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(String(warn.mock.calls[0]?.[0])).toContain('[x3dh][legacy]')
    } finally {
      convertSpy.mockRestore()
    }
  })

  it('default compat mode is strict (no silent downgrade)', () => {
    const builder = new SessionBuilder(storage, new ProtocolAddress('peer', 1))
    const convertSpy = vi.spyOn(signalCrypto, 'convertIdentityPublicToX25519').mockImplementation(() => {
      throw new Error('conversion failed')
    })

    try {
      expect(() => (builder as unknown as { resolveTheirIdentityDhPublicKey: Function }).resolveTheirIdentityDhPublicKey(new Uint8Array(32).fill(5)))
        .toThrow('X3DH strict mode rejected remote identity key conversion')
    } finally {
      convertSpy.mockRestore()
    }
  })
})

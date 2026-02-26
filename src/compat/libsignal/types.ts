import type { SessionBuilderStorage } from '../../session/builder/types'
import type { SessionCipherStorage } from '../../session/cipher/types'
import type { PreKeyBundle } from '../../session/builder/types'

export interface E2ESession extends PreKeyBundle { }

export interface SignalStorage extends SessionBuilderStorage, SessionCipherStorage {
    isTrustedIdentity(identifier: string, identityKey: Uint8Array, direction?: number): boolean | Promise<boolean>
    loadPreKey(id: number | string): Promise<{ privKey: Buffer; pubKey: Buffer } | undefined>
    removePreKey(id: number): void | Promise<void>
    loadSignedPreKey(id?: number): { privKey: Buffer; pubKey: Buffer } | Promise<{ privKey: Buffer; pubKey: Buffer }>
    getOurRegistrationId(): Promise<number> | number
    getOurIdentity(): { privKey: Buffer; pubKey: Buffer } | Promise<{ privKey: Buffer; pubKey: Buffer }>
}

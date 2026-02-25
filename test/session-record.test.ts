import { describe, expect, it } from 'vitest'
import { BaseKeyType } from '../src/ratchet-types'
import { SessionEntry, SessionRecord } from '../src/session/record'

function makeEntry(seed: number, used = seed): SessionEntry {
  const entry = new SessionEntry()
  const b = seed & 0xff

  entry.registrationId = 5000 + seed
  entry.currentRatchet = {
    ephemeralKeyPair: {
      pubKey: new Uint8Array(32).fill(b),
      privKey: new Uint8Array(32).fill((b + 1) & 0xff),
    },
    lastRemoteEphemeralKey: new Uint8Array(32).fill((b + 2) & 0xff),
    previousCounter: 0,
    rootKey: new Uint8Array(32).fill((b + 3) & 0xff),
  }
  entry.indexInfo = {
    baseKey: new Uint8Array(32).fill((b + 4) & 0xff),
    baseKeyType: BaseKeyType.THEIRS,
    closed: -1,
    used,
    created: seed,
    remoteIdentityKey: new Uint8Array(32).fill((b + 5) & 0xff),
  }

  return entry
}

describe('SessionRecord', () => {
  it('stores and returns sessions in descending last-used order', () => {
    const record = new SessionRecord()
    const a = makeEntry(1, 10)
    const b = makeEntry(2, 20)

    record.setSession(a)
    record.setSession(b)

    expect(record.getSessions()).toEqual([b, a])
    expect(record.haveOpenSession()).toBe(true)
    expect(record.getOpenSession()).toBe(a)
  })

  it('reorders after touchSession and persists through serialize/deserialize', () => {
    const record = new SessionRecord()
    const a = makeEntry(1, 1)
    const b = makeEntry(2, 2)
    record.setSession(a)
    record.setSession(b)

    record.touchSession(a, 100)
    expect(record.getSessions()).toEqual([a, b])

    const restored = SessionRecord.deserialize(record.serialize())
    expect(restored.getSessions().length).toBe(2)
    expect(restored.getSessions()[0]?.indexInfo.used).toBe(100)
  })

  it('closes, opens and clears sessions', () => {
    const record = new SessionRecord()
    const a = makeEntry(7)
    record.setSession(a)

    record.closeSession(a)
    expect(record.isClosed(a)).toBe(true)

    record.openSession(a)
    expect(record.isClosed(a)).toBe(false)

    record.deleteAllSessions()
    expect(record.getSessions()).toHaveLength(0)
    expect(Object.keys(record.getSessionsMap())).toHaveLength(0)
  })
})

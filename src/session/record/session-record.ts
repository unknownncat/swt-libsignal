import type { SerializedSessionRecord, SerializedSessionEntry } from './types'
import { SessionEntry } from './session-entry'
import { CLOSED_SESSIONS_MAX, SESSION_RECORD_VERSION } from '../constants'
import { assertUint8, toBase64 } from '../utils'
import { BaseKeyType } from '../../ratchet-types'

export class SessionRecord {
    private readonly _sessions: Record<string, SessionEntry> = {}
    private readonly _sessionIds = new WeakMap<SessionEntry, number>()
    private _nextSessionId = 0
    private _lastUsedAt = 0

    /** @deprecated Use getSessionsMap() for a readonly view. */
    get sessions(): Record<string, SessionEntry> {
        return this._sessions
    }
    private _sortedSessions: SessionEntry[] = []
    version: string = SESSION_RECORD_VERSION

    static createEntry(): SessionEntry {
        return new SessionEntry()
    }

    static deserialize(data: SerializedSessionRecord): SessionRecord {
        const obj = new SessionRecord()

        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                const deserialized = SessionEntry.deserialize(entry)
                obj._sessions[key] = deserialized
                obj.assignSessionId(deserialized)
                obj.insertIntoSortedSessions(deserialized)
            }
        }
        return obj
    }

    serialize(): SerializedSessionRecord {
        const _sessions: Record<string, SerializedSessionEntry> = {}
        for (const [key, entry] of Object.entries(this._sessions)) {
            _sessions[key] = entry.serialize()
        }
        return { _sessions, version: this.version }
    }

    getSessionsMap(): Readonly<Record<string, SessionEntry>> {
        return this._sessions
    }

    haveOpenSession(): boolean {
        const open = this.getOpenSession()
        return !!open && typeof open.registrationId === 'number'
    }

    getSession(key: Uint8Array): SessionEntry | undefined {
        assertUint8(key)
        const session = this._sessions[toBase64(key)]
        if (session?.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error('Tried to lookup a session using our basekey')
        }
        return session
    }

    getOpenSession(): SessionEntry | undefined {
        for (const session of Object.values(this._sessions)) {
            if (session.indexInfo.closed === -1) return session
        }
    }

    setSession(session: SessionEntry): void {
        this.assignSessionId(session)

        const key = toBase64(session.indexInfo.baseKey)
        const existing = this._sessions[key]
        this._sessions[key] = session

        if (existing) {
            this.removeFromSortedSessions(existing)
        }
        this.insertIntoSortedSessions(session)
    }

    touchSession(session: SessionEntry, usedAt: number = Date.now()): void {
        this.assignSessionId(session)
        const nextUsedAt = Math.max(usedAt, this._lastUsedAt + 1)
        this._lastUsedAt = nextUsedAt
        session.indexInfo.used = nextUsedAt
        this.removeFromSortedSessions(session)
        this.insertIntoSortedSessions(session)
    }

    getSessions(): SessionEntry[] {
        return this._sortedSessions
    }

    closeSession(session: SessionEntry): void {
        if (session.indexInfo.closed !== -1) return
        session.indexInfo.closed = Date.now()
    }

    openSession(session: SessionEntry): void {
        session.indexInfo.closed = -1
    }

    isClosed(session: SessionEntry): boolean {
        return session.indexInfo.closed !== -1
    }

    removeOldSessions(): void {
        const total = Object.keys(this._sessions).length
        if (total <= CLOSED_SESSIONS_MAX) return

        const closed: Array<{ key: string; closed: number }> = []
        for (const [key, session] of Object.entries(this._sessions)) {
            if (session.indexInfo.closed !== -1) {
                closed.push({ key, closed: session.indexInfo.closed })
            }
        }

        closed.sort((a, b) => a.closed - b.closed)

        const toRemove = total - CLOSED_SESSIONS_MAX
        for (let i = 0; i < toRemove && i < closed.length; i++) {
            const removedSession = this._sessions[closed[i]!.key]
            if (removedSession) {
                this.removeFromSortedSessions(removedSession)
            }
            delete this._sessions[closed[i]!.key]
        }
    }

    deleteAllSessions(): void {
        for (const key of Object.keys(this._sessions)) {
            delete this._sessions[key]
        }
        this._sortedSessions = []
    }


    private assignSessionId(session: SessionEntry): number {
        const existing = this._sessionIds.get(session)
        if (existing !== undefined) return existing

        const assigned = ++this._nextSessionId
        this._sessionIds.set(session, assigned)
        return assigned
    }

    private removeFromSortedSessions(session: SessionEntry): void {
        const index = this._sortedSessions.indexOf(session)
        if (index >= 0) {
            this._sortedSessions.splice(index, 1)
        }
    }

    private insertIntoSortedSessions(session: SessionEntry): void {
        const used = session.indexInfo.used ?? 0
        this._lastUsedAt = Math.max(this._lastUsedAt, used)

        const sessionId = this.assignSessionId(session)
        let low = 0
        let high = this._sortedSessions.length

        while (low < high) {
            const mid = (low + high) >> 1
            const midSession = this._sortedSessions[mid]!
            const midUsed = midSession.indexInfo.used ?? 0
            const midId = this.assignSessionId(midSession)

            if (midUsed > used || (midUsed === used && midId > sessionId)) {
                low = mid + 1
            } else {
                high = mid
            }
        }

        this._sortedSessions.splice(low, 0, session)
    }
}

export interface SignalLogger {
    debug(event: 'ratchet-rotate' | 'queue-size' | 'queue-timeout', context?: Readonly<Record<string, number | string>>): void
    warn(event: 'identity-verification-failed', context?: Readonly<Record<string, number | string>>): void
}

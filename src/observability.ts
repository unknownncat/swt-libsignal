export type SignalLogContextValue = number | string | boolean

export type SignalDebugEvent =
    | 'ratchet-rotate'
    | 'queue-size'
    | 'queue-timeout'
    | 'worker-dispatch'
    | 'worker-buffered'
    | 'worker-revive'

export type SignalInfoEvent =
    | 'worker-ready'
    | 'worker-close'

export type SignalWarnEvent =
    | 'identity-verification-failed'
    | 'compat-fallback-used'
    | 'worker-backpressure'

export type SignalErrorEvent =
    | 'worker-crash'

export interface SignalLogger {
    debug(event: SignalDebugEvent, context?: Readonly<Record<string, SignalLogContextValue>>): void
    info?(event: SignalInfoEvent, context?: Readonly<Record<string, SignalLogContextValue>>): void
    warn(event: SignalWarnEvent, context?: Readonly<Record<string, SignalLogContextValue>>): void
    error?(event: SignalErrorEvent, context?: Readonly<Record<string, SignalLogContextValue>>): void
}

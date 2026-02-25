// Base Error

export class SignalError extends Error {
    constructor(
        message?: string,
        options?: { cause?: unknown }
    ) {
        super(message, options)

        // define automaticamente o nome da classe
        this.name = new.target.name

        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, new.target)
        }
    }
}


// Identity Trust Error

export class UntrustedIdentityKeyError extends SignalError {
    public readonly addr: string
    public readonly identityKey: Uint8Array

    constructor(
        addr: string,
        identityKey: Uint8Array,
        options?: { cause?: unknown }
    ) {
        super(
            `Untrusted identity key for ${addr}`,
            options
        )

        this.addr = addr
        this.identityKey = identityKey
    }
}

// Session Errors


export class SessionError extends SignalError { }

export class SessionStateError extends SessionError {
    readonly code = 'SESSION_STATE_ERROR'
}

export class SessionDecryptFailed extends SessionError {
    readonly code = 'SESSION_DECRYPT_FAILED'
}

export class MessageCounterError extends SessionError { }

export class PreKeyError extends SessionError { }

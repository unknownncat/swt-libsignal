import type { SignalLogger } from '../observability'

let logger: SignalLogger | undefined

export function setSignalLogger(next?: SignalLogger): void {
    logger = next
}

export function getSignalLogger(): SignalLogger | undefined {
    return logger
}

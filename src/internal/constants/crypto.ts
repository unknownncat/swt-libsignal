export const TEXT_ENCODER = new TextEncoder()
export const HKDF_INFO_WHISPER_TEXT = TEXT_ENCODER.encode('WhisperText')

/**
 * Returns a fresh zeroed buffer to avoid accidental shared-state mutation.
 */
export function zero32(): Uint8Array {
    return new Uint8Array(32)
}

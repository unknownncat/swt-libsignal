export function secureZero(buf?: Uint8Array | null): void {
    if (!buf) return;

    buf.fill(0);
}
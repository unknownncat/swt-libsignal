export class Deque<T> {
    private _queue: T[]
    private _offset: number

    constructor() {
        this._queue = []
        this._offset = 0
    }

    push(item: T): void {
        this._queue.push(item)
    }

    shift(): T | undefined {
        const offset = this._offset
        const queue = this._queue

        if (offset >= queue.length) {
            return undefined
        }

        const value = queue[offset]
        this._offset = offset + 1

        // Reset imediato se esvaziou
        if (this._offset === queue.length) {
            this._queue = []
            this._offset = 0
            return value
        }

        // Compact heurística amortizada O(1)
        if (offset > 0 && offset >= (queue.length >> 1)) {
            this._queue = queue.slice(this._offset)
            this._offset = 0
        }

        return value
    }

    spliceFront(n: number): void {
        if (n <= 0) return

        const newOffset = this._offset + n
        const queue = this._queue

        if (newOffset >= queue.length) {
            this._queue = []
            this._offset = 0
            return
        }

        this._offset = newOffset

        if (newOffset >= (queue.length >> 1)) {
            this._queue = queue.slice(newOffset)
            this._offset = 0
        }
    }

    get length(): number {
        return this._queue.length - this._offset
    }

    at(index: number): T | undefined {
        if (index < 0) return undefined
        return this._queue[this._offset + index]
    }

    clear(): void {
        this._queue = []
        this._offset = 0
    }
}
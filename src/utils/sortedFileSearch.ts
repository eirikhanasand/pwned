import { open } from 'fs/promises'

const CHUNK_SIZE = 64 * 1024

export type SortedFileMatch = {
    offset: number
}

function comparePasswordBytes(left: Buffer, right: Buffer): number {
    return Buffer.compare(left, right)
}

async function readChunk(handle: Awaited<ReturnType<typeof open>>, start: number, end: number): Promise<Buffer> {
    const length = Math.max(0, end - start)
    const buffer = Buffer.alloc(length)
    const { bytesRead } = await handle.read(buffer, 0, length, start)
    return buffer.subarray(0, bytesRead)
}

function trimCarriageReturn(line: Buffer): Buffer {
    return line.at(-1) === 0x0d ? line.subarray(0, -1) : line
}

export async function readFileBoundaries(filePath: string): Promise<{ firstLine: string, lastLine: string, sizeBytes: number }> {
    const handle = await open(filePath, 'r')

    try {
        const stat = await handle.stat()
        if (stat.size === 0) {
            throw new Error(`${filePath} is empty`)
        }

        const firstText = (await readChunk(handle, 0, Math.min(stat.size, CHUNK_SIZE))).toString('utf8')
        const firstLine = firstText.split(/\r?\n/)[0] ?? ''

        let position = stat.size
        let tailText = ''

        while (position > 0) {
            const nextPosition = Math.max(0, position - CHUNK_SIZE)
            tailText = (await readChunk(handle, nextPosition, position)).toString('utf8') + tailText

            const lines = tailText.split(/\r?\n/).filter(line => line.length > 0)
            if (lines.length > 0) {
                return {
                    firstLine,
                    lastLine: lines.at(-1) ?? '',
                    sizeBytes: stat.size
                }
            }

            position = nextPosition
        }

        throw new Error(`${filePath} does not contain any lines`)
    } finally {
        await handle.close()
    }
}

async function readLineStartingAt(handle: Awaited<ReturnType<typeof open>>, offset: number, sizeBytes: number): Promise<{ line: Buffer, offset: number } | null> {
    if (offset >= sizeBytes) {
        return null
    }

    let cursor = offset
    let buffer = Buffer.alloc(0)

    while (cursor < sizeBytes) {
        const chunk = await readChunk(handle, cursor, Math.min(sizeBytes, cursor + CHUNK_SIZE))
        if (!chunk.length) {
            break
        }

        buffer = Buffer.concat([buffer, chunk])
        const newlineIndex = buffer.indexOf(0x0a)

        if (newlineIndex !== -1) {
            return {
                line: trimCarriageReturn(buffer.subarray(0, newlineIndex)),
                offset
            }
        }

        cursor += chunk.byteLength
    }

    return buffer.byteLength ? { line: trimCarriageReturn(buffer), offset } : null
}

async function readLineAtOrBefore(handle: Awaited<ReturnType<typeof open>>, offset: number, sizeBytes: number): Promise<{ line: Buffer, offset: number } | null> {
    if (sizeBytes === 0) {
        return null
    }

    const endExclusive = Math.min(sizeBytes, offset + 1)
    let position = endExclusive
    let suffix = Buffer.alloc(0)
    let lineStart = 0

    while (position > 0) {
        const nextPosition = Math.max(0, position - CHUNK_SIZE)
        suffix = Buffer.concat([await readChunk(handle, nextPosition, position), suffix])

        const searchEnd = Math.max(0, suffix.byteLength - 2)
        const newlineIndex = suffix.lastIndexOf(0x0a, searchEnd)
        if (newlineIndex !== -1) {
            lineStart = endExclusive - suffix.byteLength + newlineIndex + 1
            break
        }

        position = nextPosition
    }

    return readLineStartingAt(handle, lineStart, sizeBytes)
}

async function findLowerBound(handle: Awaited<ReturnType<typeof open>>, query: Buffer, sizeBytes: number): Promise<number | null> {
    let low = 0
    let high = sizeBytes
    let attempts = 0
    let candidateOffset: number | null = null

    while (low < high && attempts < 96) {
        attempts += 1
        const mid = Math.floor((low + high) / 2)
        const lineResult = await readLineAtOrBefore(handle, mid, sizeBytes)

        if (!lineResult) {
            high = mid
            continue
        }

        const comparison = comparePasswordBytes(lineResult.line, query)
        if (comparison < 0) {
            low = Math.max(lineResult.offset + lineResult.line.byteLength + 1, low + 1)
            continue
        }

        candidateOffset = lineResult.offset
        high = Math.max(0, lineResult.offset)
    }

    return candidateOffset
}

export async function searchSortedFileExactMatch(filePath: string, query: string): Promise<SortedFileMatch | null> {
    const handle = await open(filePath, 'r')
    const queryBytes = Buffer.from(query, 'utf8')

    try {
        const stat = await handle.stat()
        const startOffset = await findLowerBound(handle, queryBytes, stat.size)
        if (startOffset === null) {
            return null
        }

        const lineResult = await readLineStartingAt(handle, startOffset, stat.size)
        if (!lineResult || comparePasswordBytes(lineResult.line, queryBytes) !== 0) {
            return null
        }

        return {
            offset: lineResult.offset
        }
    } finally {
        await handle.close()
    }
}

export async function searchSortedFileExact(filePath: string, query: string): Promise<boolean> {
    return (await searchSortedFileExactMatch(filePath, query)) !== null
}

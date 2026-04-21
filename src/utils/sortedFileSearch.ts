import { open } from 'fs/promises'

const CHUNK_SIZE = 64 * 1024

function comparePasswords(left: string, right: string): number {
    return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'))
}

async function readChunk(handle: Awaited<ReturnType<typeof open>>, start: number, end: number): Promise<string> {
    const length = Math.max(0, end - start)
    const buffer = Buffer.alloc(length)
    const { bytesRead } = await handle.read(buffer, 0, length, start)
    return buffer.subarray(0, bytesRead).toString('utf8')
}

export async function readFileBoundaries(filePath: string): Promise<{ firstLine: string, lastLine: string, sizeBytes: number }> {
    const handle = await open(filePath, 'r')

    try {
        const stat = await handle.stat()
        if (stat.size === 0) {
            throw new Error(`${filePath} is empty`)
        }

        const firstText = await readChunk(handle, 0, Math.min(stat.size, CHUNK_SIZE))
        const firstLine = firstText.split(/\r?\n/)[0] ?? ''

        let position = stat.size
        let tailText = ''

        while (position > 0) {
            const nextPosition = Math.max(0, position - CHUNK_SIZE)
            tailText = await readChunk(handle, nextPosition, position) + tailText

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

async function readLineAtOrAfter(handle: Awaited<ReturnType<typeof open>>, offset: number, sizeBytes: number): Promise<{ line: string, offset: number } | null> {
    if (offset >= sizeBytes) {
        return null
    }

    let cursor = offset
    let text = ''

    while (cursor < sizeBytes) {
        const chunk = await readChunk(handle, cursor, Math.min(sizeBytes, cursor + CHUNK_SIZE))
        if (!chunk.length) {
            break
        }

        text += chunk
        const newlineIndex = text.indexOf('\n')

        if (offset === 0) {
            if (newlineIndex === -1) {
                cursor += chunk.length
                continue
            }

            return {
                line: text.slice(0, newlineIndex).replace(/\r$/, ''),
                offset: 0
            }
        }

        if (newlineIndex === -1) {
            cursor += chunk.length
            continue
        }

        const lineStartOffset = cursor - (text.length - chunk.length) + newlineIndex + 1
        const remaining = text.slice(newlineIndex + 1)
        const nextNewline = remaining.indexOf('\n')

        if (nextNewline === -1) {
            cursor += chunk.length
            continue
        }

        return {
            line: remaining.slice(0, nextNewline).replace(/\r$/, ''),
            offset: lineStartOffset
        }
    }

    return null
}

export async function searchSortedFileExact(filePath: string, query: string): Promise<boolean> {
    const handle = await open(filePath, 'r')

    try {
        const stat = await handle.stat()
        let low = 0
        let high = stat.size
        let attempts = 0

        while (low < high && attempts < 64) {
            attempts += 1
            const mid = Math.floor((low + high) / 2)
            const lineResult = await readLineAtOrAfter(handle, mid, stat.size)

            if (!lineResult) {
                break
            }

            const comparison = comparePasswords(lineResult.line, query)
            if (comparison === 0) {
                return true
            }

            if (comparison < 0) {
                low = Math.max(lineResult.offset + Buffer.byteLength(lineResult.line, 'utf8') + 1, low + 1)
            } else {
                high = Math.max(0, lineResult.offset)
            }
        }

        return false
    } finally {
        await handle.close()
    }
}

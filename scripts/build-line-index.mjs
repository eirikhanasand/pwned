import { createReadStream } from 'node:fs'
import { stat, writeFile } from 'node:fs/promises'
import path from 'node:path'

const filePath = process.argv[2]
const checkpointEveryLines = Number(process.env.LINE_INDEX_EVERY || 250_000)

if (!filePath) {
    console.error('Usage: node scripts/build-line-index.mjs <sorted-password-file>')
    process.exit(1)
}

if (!Number.isFinite(checkpointEveryLines) || checkpointEveryLines < 1) {
    console.error('LINE_INDEX_EVERY must be a positive number')
    process.exit(1)
}

const absoluteFilePath = path.resolve(filePath)
const stats = await stat(absoluteFilePath)
const checkpoints = [{ offset: 0, line: 1 }]
let offset = 0
let line = 1
let nextCheckpointLine = checkpointEveryLines + 1

await new Promise((resolve, reject) => {
    const stream = createReadStream(absoluteFilePath)

    stream.on('data', chunk => {
        for (let index = 0; index < chunk.length; index += 1) {
            if (chunk[index] !== 0x0a) continue

            line += 1
            const nextLineOffset = offset + index + 1
            if (line >= nextCheckpointLine) {
                checkpoints.push({ offset: nextLineOffset, line })
                nextCheckpointLine += checkpointEveryLines
            }
        }

        offset += chunk.length
    })

    stream.on('error', reject)
    stream.on('end', resolve)
})

const index = {
    version: 1,
    file: absoluteFilePath,
    sizeBytes: stats.size,
    checkpointEveryLines,
    generatedAt: new Date().toISOString(),
    checkpoints,
}

await writeFile(`${absoluteFilePath}.line-index.json`, `${JSON.stringify(index)}\n`, 'utf8')
console.log(JSON.stringify({
    file: absoluteFilePath,
    sizeBytes: stats.size,
    lineCount: line - 1,
    checkpoints: checkpoints.length,
    indexPath: `${absoluteFilePath}.line-index.json`,
}))

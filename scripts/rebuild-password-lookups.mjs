import { createReadStream, promises as fs } from 'fs'
import path from 'path'
import readline from 'readline'

const passwordsDir = process.env.PASSWORDS_DIR || path.join(process.cwd(), 'passwords')
const requestedDatasets = process.argv.slice(2)

async function listDatasets() {
    if (requestedDatasets.length) {
        return requestedDatasets
    }

    const entries = await fs.readdir(passwordsDir, { withFileTypes: true })
    return entries
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
        .sort()
}

async function readFirstAndLastLine(filePath) {
    const stream = createReadStream(filePath, { encoding: 'utf8' })
    const rl = readline.createInterface({
        input: stream,
        crlfDelay: Infinity
    })

    let first = null
    let last = null

    for await (const line of rl) {
        if (first === null) {
            first = line
        }

        last = line
    }

    rl.close()
    stream.close()

    if (first === null || last === null) {
        throw new Error(`${filePath} does not contain any lines`)
    }

    return { first, last }
}

async function rebuildDataset(dataset) {
    const datasetDir = path.join(passwordsDir, dataset)
    const entries = await fs.readdir(datasetDir, { withFileTypes: true })
    const shardFiles = entries
        .filter(entry => entry.isFile())
        .map(entry => entry.name)
        .filter(name => name !== 'lookup.txt')
        .filter(name => !name.endsWith('.zip') && !name.endsWith('.7z'))
        .filter(name => name !== `${dataset}.txt` && name !== `${dataset}_sorted.txt`)
        .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }))

    if (!shardFiles.length) {
        throw new Error(`No shard files found in ${datasetDir}`)
    }

    const lines = []

    for (const file of shardFiles) {
        const filePath = path.join(datasetDir, file)
        const { first, last } = await readFirstAndLastLine(filePath)
        lines.push(file, first, last)
    }

    await fs.writeFile(path.join(datasetDir, 'lookup.txt'), `${lines.join('\n')}\n`, 'utf8')
    return {
        dataset,
        shards: shardFiles.length
    }
}

async function main() {
    const datasets = await listDatasets()
    const results = []

    for (const dataset of datasets) {
        const lookupPath = path.join(passwordsDir, dataset, 'lookup.txt')
        try {
            await fs.access(lookupPath)
        } catch {
            continue
        }

        results.push(await rebuildDataset(dataset))
    }

    console.log(JSON.stringify({
        ok: true,
        rebuiltAt: new Date().toISOString(),
        datasetCount: results.length,
        results
    }, null, 2))
}

main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
})

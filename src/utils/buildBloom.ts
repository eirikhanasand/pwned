import fs from 'fs'
import path from 'path'
import readline from 'readline'
import pkg from 'bloom-filters'
const { BloomFilter } = pkg

const PASSWORD_DIR = './passwords'
const BLOOM_DIR = './bloom'
const FALSE_POS_RATE = 0.01
let estimatedPasswords = 15_000_000

if (!fs.existsSync(BLOOM_DIR)) {
    fs.mkdirSync(BLOOM_DIR)
}

export default async function buildBloomPerFile() {
    const files = fs.readdirSync(PASSWORD_DIR).filter(f => f.endsWith('.txt'))
    let count = 0

    for (const file of files) {
        const filePath = path.join(PASSWORD_DIR, file)
        console.log(`Processing file ${++count}/${files.length}: ${file}`)

        const bloom = BloomFilter.create(estimatedPasswords, FALSE_POS_RATE)
        await processFile(filePath, bloom)

        const bloomJson = JSON.stringify(bloom.saveAsJSON())
        const savePath = path.join(BLOOM_DIR, `${file}.bloom`)
        fs.writeFileSync(savePath, bloomJson)
        console.log(`Saved Bloom filter: ${savePath}`)
    }

    console.log('All Bloom filters built.')
}

async function processFile(filePath: string, bloom: InstanceType<typeof BloomFilter>) {
    return new Promise((resolve, reject) => {
        const rl = readline.createInterface({
            input: fs.createReadStream(filePath),
            crlfDelay: Infinity
        })

        rl.on('line', (line) => {
            if (line.length > 0) bloom.add(line)
        })

        rl.on('close', resolve)
        rl.on('error', reject)
    })
}

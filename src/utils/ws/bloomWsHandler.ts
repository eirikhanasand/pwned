// import pkg from 'bloom-filters'
import checkPwnedPassword from '#utils/pwnedCheck.ts'
import execPipeAndBroadcast from './pipeAndBroadcast.ts'
import broadcast from './broadcast.ts'

// const { BloomFilter } = pkg

export default async function bloomWsHandler(id: string, password: string) {
    const count = await checkPwnedPassword(password)
    if (!count) {
        return broadcast(id, 'update', { ok: true })
    }

    broadcast(id, 'update', { ok: false, count })

    // const BLOOM_DIR = 'bloom'
    // const files = fs.readdirSync(BLOOM_DIR).filter(f => f.endsWith('.bloom'))

    // const blooms = files.map(file => {
    //     const data = fs.readFileSync(path.join(BLOOM_DIR, file))
    //     const filter = BloomFilter.fromJSON(JSON.parse(data.toString()))
    //     return { file, filter }
    // })

    // const matches = blooms
    //     .filter(({ filter }) => filter.has(password))
    //     .map(({ file }) => file)

    execPipeAndBroadcast(id, password)
}

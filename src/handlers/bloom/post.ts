import fs from 'fs'
import path from 'path'
import type { FastifyRequest, FastifyReply } from 'fastify'
import pkg from 'bloom-filters'
const { BloomFilter } = pkg

export default async function bloomHandler(req: FastifyRequest, res: FastifyReply) {
    const BLOOM_DIR = 'bloom'
    const files = fs.readdirSync(BLOOM_DIR).filter(f => f.endsWith('.bloom'))

    const blooms: InstanceType<typeof BloomFilter>[] = files.map(file => {
        const data = fs.readFileSync(path.join(BLOOM_DIR, file))
        return BloomFilter.fromJSON(JSON.parse(data.toString()))
    })

    const { password } = (await req.body as { password: string }) || {}
    const isLeaked = blooms.some(bloom => bloom.has(password))
    if (isLeaked) {
        return res.send({ ok: false, reason: 'Known compromised password' })
    }

    return res.send({ ok: true })
}

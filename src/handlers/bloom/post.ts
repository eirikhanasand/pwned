import fs from 'fs'
import path from 'path'
import type { FastifyRequest, FastifyReply } from 'fastify'
import pkg from 'bloom-filters'
const { BloomFilter } = pkg

export default async function bloomHandler(req: FastifyRequest, res: FastifyReply) {
    const { password } = (await req.body as { password: string }) || {}
    if (!password) {
        return res.send({ ok: false, reason: 'No password provided.' })
    }

    const BLOOM_DIR = 'bloom'
    const files = fs.readdirSync(BLOOM_DIR).filter(f => f.endsWith('.bloom'))

    const blooms = files.map(file => {
        const data = fs.readFileSync(path.join(BLOOM_DIR, file))
        const filter = BloomFilter.fromJSON(JSON.parse(data.toString()))
        return { file, filter }
    })

    const matches = blooms
        .filter(({ filter }) => filter.has(password))
        .map(({ file }) => file)

    if (matches.length > 0) {
        return res.send({
            ok: false,
            reason: 'Known compromised password',
            sourceFiles: matches
        })
    }

    return res.send({ ok: true })
}

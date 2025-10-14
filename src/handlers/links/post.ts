import run from '#db'
import { randomUUID } from 'crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function postLink(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }
        const { path } = req.body as { path?: string } ?? {}

        if (!path) {
            return res.status(400).send({ error: 'Missing path' })
        }

        const query = `
            INSERT INTO links (id, path)
            VALUES ($1, $2)
            ON CONFLICT (id)
            DO NOTHING;
        `
        
        const randomId = randomUUID().slice(0, 6)
        const result = await run(query, [id || randomId, path])

        if (!result || result.rowCount === 0) {
            return res.status(409).send({ error: 'Shortcut already taken' })
        }

        return res.status(201).send({ id: id || randomId, path })
    } catch (error) {
        console.log(`Error creating shortcut: ${error}`)
        return res.status(500).send({ error: 'Failed to create shortcut' })
    }
}

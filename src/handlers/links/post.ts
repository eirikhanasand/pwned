import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function postLink(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id, path } = req.body as { id?: string, path?: string }

        if (!id || !path) {
            return res.status(400).send({ error: 'Missing id or path' })
        }

        const query = `
        INSERT INTO links (id, path)
        VALUES ($1, $2)
        ON CONFLICT (id)
        DO NOTHING;
        `
        const result = await run(query, [id, path])

        if (!result || result.rowCount === 0) {
            return res.status(409).send({ error: 'Shortcut already taken' })
        }

        return res.status(201).send(result.rows[0])
    } catch (error) {
        console.log(`Error creating shortcut: ${error}`)
        return res.status(500).send({ error: 'Failed to create shortcut' })
    }
}

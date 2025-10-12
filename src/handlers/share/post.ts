import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function postShare(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id, path, content } = req.body as { id?: string, path?: string; content?: string }

        if (!id || !path || !content) {
            return res.status(400).send({ error: 'Missing required fields: id, path or content' })
        }

        const query = `
        INSERT INTO share (id, path, content)
        VALUES ($1, $2, $3)
        RETURNING *
        `
        const result = await run(query, [id, path, content])

        if (!result || result.rowCount === 0) {
            return res.status(500).send({ error: 'Failed to create share' })
        }

        return res.status(201).send({ data: result.rows[0] })
    } catch (error) {
        console.log(`Error creating share: ${error}`)
        return res.status(500).send({ error: 'Failed to create share' })
    }
}

import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function updateShare(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }
        const { path, content } = req.body as { path?: string; content?: string }

        if (!id) {
            return res.status(400).send({ error: 'Missing share ID' })
        }

        if (!content) {
            return res.status(400).send({ error: 'No content' })
        }

        const query = `
        UPDATE shares
        SET
            path = COALESCE($2, path),
            content = COALESCE($3, content)
        WHERE id = $1
        RETURNING *
        `
        const result = await run(query, [id, path || null, content])

        if (!result || result.rowCount === 0) {
            return res.status(404).send({ error: 'Share not found' })
        }

        return res.status(200).send({ data: result.rows[0] })
    } catch (error) {
        console.error(`Error updating share: ${error}`)
        return res.status(500).send({ error: 'Failed to update share' })
    }
}

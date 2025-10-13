import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function putLink(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }
        const { path } = req.body as { path?: string }

        if (!id) {
            return res.status(400).send({ error: 'Missing link ID' })
        }

        const query = `
        UPDATE links
        SET
            path = COALESCE($2, path),
        WHERE id = $1
        RETURNING *
        `
        const result = await run(query, [id, path || null])

        if (!result || result.rowCount === 0) {
            return res.status(404).send({ error: 'Link not found' })
        }

        return res.status(200).send(result.rows[0])
    } catch (error) {
        console.log(`Error updating shortcut: ${error}`)
        return res.status(500).send({ error: 'Failed to update shortcut' })
    }
}

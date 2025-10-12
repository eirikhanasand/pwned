import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

export default async function deleteFile(req: FastifyRequest, res: FastifyReply) {
    const { id } = req.params as { id: string }

    if (!id) {
        return res.status(400).send({ error: 'Missing image ID' })
    }

    try {
        const result = await run(
            'DELETE FROM files WHERE id = $1 RETURNING id',
            [id]
        )

        if (result.rows.length === 0) {
            return res.status(404).send({ error: 'Image not found' })
        }

        return { deleted: result.rows[0].id }
    } catch (error) {
        console.error('Error deleting image:', error)
        return res.status(500).send({ error: 'Internal server error' })
    }
}

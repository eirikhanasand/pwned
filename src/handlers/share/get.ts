import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function getShare(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }

        if (!id) {
            return res.status(400).send({ error: 'Missing share ID' })
        }

        const query = 'SELECT * FROM shares WHERE id = $1'
        const result = await run(query, [id])

        if (!result || result.rowCount === 0) {
            return res.status(404).send({ error: 'Share not found' })
        }

        return res.status(200).send({ data: result.rows[0] })
    } catch (error) {
        console.error(`Error fetching share: ${error}`)
        return res.status(500).send({ error: 'Failed to fetch share' })
    }
}

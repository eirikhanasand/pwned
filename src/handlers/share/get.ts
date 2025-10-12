import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function getShare(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }

        if (!id) {
            return res.status(400).send({ error: 'Missing share ID' })
        }

        try {
            const result = await queryShare(id)

            if (result === 404) {
                throw new Error("Share not found")
            }

            return res.status(200).send({ data: result.rows[0] })
        } catch (error) {
            return res.status(404).send({ error: 'Share not found' })
        }
    } catch (error) {
        console.error(`Error fetching share: ${error}`)
        return res.status(500).send({ error: 'Failed to fetch share' })
    }
}

async function queryShare(id: string) {
    const query = 'SELECT * FROM share WHERE id = $1'
    const result = await run(query, [id])

    if (!result || result.rowCount === 0) {
        const query = `
        INSERT INTO share (id, content)
        VALUES ($1, $2)
        RETURNING *
        `
        const insertResult = await run(query, [id, ""])
        if (insertResult) {
            const query = 'SELECT * FROM share WHERE id = $1'
            const result = await run(query, [id])
            return result
        }
    }

    return 404
}

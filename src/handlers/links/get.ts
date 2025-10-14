import run from '#db'
import type { FastifyReply, FastifyRequest } from 'fastify'

export default async function getLink(req: FastifyRequest, res: FastifyReply) {
    try {
        const { id } = req.params as { id: string }

        if (!id) {
            return res.status(400).send({ error: 'Missing link ID' })
        }
        
        try {
            const result = await queryLinks(id)
            if (!result) {
                throw new Error('Link not found')
            }

            return res.status(200).send(result)
        } catch (error) {
            return res.status(404).send({ error: 'Link not found' })
        }
    } catch (error) {
        console.log(`Error fetching link: ${error}`)
        return res.status(500).send({ error: 'Failed to fetch link' })
    }
}

async function queryLinks(id: string) {
    const updateQuery = `
        UPDATE links
        SET visits = visits + 1
        WHERE id = $1
        RETURNING *;
    `
    const updateResult = await run(updateQuery, [id])

    if (updateResult?.rowCount && updateResult.rowCount > 0) {
        return updateResult.rows[0]
    }

    return null
}

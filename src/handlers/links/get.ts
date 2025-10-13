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
            
            if (result === 404) {
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
    const query = 'SELECT * FROM links WHERE id = $1'
    const result = await run(query, [id])

    if (!result || result.rowCount === 0) {
        const query = `INSERT INTO links (id) VALUES ($1) RETURNING *`
        const insertResult = await run(query, [id])
        if (insertResult) {
            const query = 'SELECT * FROM links WHERE id = $1'
            const result = await run(query, [id])
            return result.rows[0]
        }
    }

    if (result.rowCount && result.rowCount > 0) {
        const updateQuery = `UPDATE links SET visits = visits + 1 WHERE id = $1 RETURNING *`
        await run(updateQuery, [id])
        return { ...result.rows[0], visits: result.rows[0].visits + 1 }
    }

    return 404
}

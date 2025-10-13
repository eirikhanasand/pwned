import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

export default async function checkPath(req: FastifyRequest, res: FastifyReply) {
    const { path } = req.query as { path: string }

    if (!path) {
        return res.status(400).send({ error: "Path query parameter is required" })
    }

    try {
        const result = await run(
            "SELECT id FROM files WHERE path = $1 LIMIT 1",
            [path]
        )

        if (result.rows.length === 0) {
            return res.send({ exists: false })
        } else {
            return res.send({ exists: true, id: result.rows[0].id })
        }
    } catch (err) {
        console.error(err)
        return res.status(500).send({ error: "Internal server error" })
    }
}

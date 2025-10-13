import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

export default async function getFile(req: FastifyRequest, res: FastifyReply) {
    const { id } = req.params as { id: string }

    try {
        const result = await run(
            "SELECT id, name, description, data, type, path, uploaded_at FROM files WHERE id = $1",
            [id]
        )

        if (result.rows.length === 0) {
            return res.status(404).send({ error: "File not found" })
        }

        const file = result.rows[0]
        res.header("Content-Type", file.type)
        res.header("Content-Disposition", `inline; filename="${file.name}"`)
        return res.send(file.data)
    } catch (err) {
        console.log(err)
        res.status(500).send({ error: "Internal server error" })
    }
}

import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

export default async function getFileByPath(req: FastifyRequest, res: FastifyReply) {
    const { id } = req.params as { id: string }

    try {
        const result = await run(
            "SELECT id, name, description, data, type, path, uploaded_at FROM images WHERE path = $1",
            [id]
        )

        if (result.rows.length === 0) {
            return res.status(404).send({ error: "Image not found" })
        }
        const image = result.rows[0]
        res.header("Content-Type", "application/octet-stream")
        return image.data
    } catch (err) {
        console.log(err)
        res.status(500).send({ error: "Internal server error" })
    }
}

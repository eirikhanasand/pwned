import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

type PostFileProps = {
    name: string
    description: string
    data: string
    path: string
    type: string
}

export default async function postFile(req: FastifyRequest, res: FastifyReply) {
    const { name, description, data, path, type } = req.body as PostFileProps

    if (!name || !data) {
        return res.status(400).send({ error: "Missing name or image data" })
    }

    const buffer = Buffer.from(data, "base64")

    try {
        const result = await run(
            `INSERT INTO files (name, description, data, path, type)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id`,
            [name, description || null, buffer, path, type]
        )

        return { id: result.rows[0].id }
    } catch (error) {
        console.log(error)
        return res.status(500).send({ error: "Internal server error" })
    }
}

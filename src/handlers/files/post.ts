import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'
import { randomUUID } from 'crypto'

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
    const id = randomUUID().slice(0, 6)

    try {
        await run(
            `INSERT INTO files (id, name, description, data, path, type)
            VALUES ($1, $2, $3, $4, $5, $6);`,
            [id, name, description || null, buffer, path, type]
        )

        return { id }
    } catch (error) {
        console.log(error)
        return res.status(500).send({ error: "Internal server error" })
    }
}

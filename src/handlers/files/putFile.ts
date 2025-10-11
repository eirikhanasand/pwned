import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'

type PutFileProps = {
    name: string
    description: string
    data: string
}

export default async function putFile(req: FastifyRequest, res: FastifyReply) {
    const { id } = req.params as { id: string }
    const { name, description, data } = req.body as PutFileProps

    if (!name && !description && !data) {
        return res.status(400).send({ error: "Nothing to update" })
    }

    const updates = []
    const values = []
    let idx = 1

    if (name) {
        updates.push(`name = $${idx++}`)
        values.push(name)
    }

    if (description) {
        updates.push(`description = $${idx++}`)
        values.push(description)
    }

    if (data) {
        updates.push(`data = $${idx++}`)
        values.push(Buffer.from(data, "base64"))
    }

    values.push(id)

    const sql = `UPDATE images SET ${updates.join(", ")} WHERE id = $${idx} RETURNING id`

    try {
        const result = await run(sql, values)

        if (result.rows.length === 0) {
            return res.status(404).send({ error: "Image not found" })
        }

        return { updated: result.rows[0].id }
    } catch (error) {
        console.log(error)
        return res.status(500).send({ error: "Internal server error" })
    }
}

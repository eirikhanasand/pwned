import type { FastifyReply, FastifyRequest } from 'fastify'
import run from '#utils/db.ts'
import { randomUUID } from 'crypto'

type MultipartValue<T = unknown> = MultipartFile | MultipartField<T>

interface MultipartFile {
    type: 'file'
    fieldname: string
    filename: string
    encoding: string
    mimetype: string
    file: NodeJS.ReadableStream
}

interface MultipartField<T = string> {
    type: 'field'
    fieldname: string
    value: T
}

export default async function postFile(req: FastifyRequest, res: FastifyReply) {
    if (!req.isMultipart?.()) {
        return res.status(400).send({ error: "Request is not multipart" })
    }

    try {
        const parts: {
            name?: string
            description?: string
            path?: string
            type?: string
            fileBuffer?: Buffer
        } = {}


        for await (const part of req.parts() as AsyncIterable<MultipartValue>) {
            if (part.type === 'file') {
                const filePart = part as MultipartFile
                parts.fileBuffer = await streamToBuffer(filePart.file)
            } else {
                const fieldName = part.fieldname
                const value = part.value
                if (['name', 'description', 'path', 'type'].includes(fieldName)) {
                    (parts as any)[fieldName] = value
                }
            }
        }

        const { name, description, path, type, fileBuffer } = parts

        if (!name || !fileBuffer || !type) {
            return res.status(400).send({ error: "Missing required fields: name, file, or type" })
        }

        const id = randomUUID().slice(0, 6)
        const filePath = path || id

        const result = await run(
            `INSERT INTO files (id, name, description, data, path, type)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (path) DO UPDATE
            SET path = EXCLUDED.path
            RETURNING 
              CASE 
                WHEN xmax = 0 THEN 'ok'
                ELSE 'conflict'
              END AS status;`,
            [id, name, description || null, fileBuffer, filePath, type]
        )

        if (result.rows[0].status === 'conflict') {
            return res.status(409).send({ error: `Path '${filePath}' taken` })
        }

        console.log("sent off", {id})
        return res.send({ id })
    } catch (error) {
        console.error(error)
        return res.status(500).send({ error: "Internal server error" })
    }
}

function streamToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const chunks: Uint8Array[] = []
        stream.on('data', (chunk) => chunks.push(chunk))
        stream.on('end', () => resolve(Buffer.concat(chunks)))
        stream.on('error', reject)
    })
}

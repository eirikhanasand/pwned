import type { FastifyRequest, FastifyReply } from 'fastify'
import checkPwnedPassword from '#utils/pwnedCheck.ts'

export default async function pwnedHandler(req: FastifyRequest, res: FastifyReply) {
    const { password } = (await req.body as { password: string }) || {}
    if (!password) {
        return res.send({ ok: false, reason: 'No password provided.' })
    }

    const count = await checkPwnedPassword(password)

    if (count > 0) {
        return res.send({ ok: false, count })
    }

    return res.send({ ok: true })
}

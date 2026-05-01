import type { FastifyRequest, FastifyReply } from 'fastify'
import { hasLocalPassword } from '#utils/localPasswordSearch.ts'
import checkPwnedPassword from '#utils/pwnedCheck.ts'

export default async function pwnedHandler(req: FastifyRequest, res: FastifyReply) {
    const { password } = (await req.body as { password: string }) || {}
    if (!password) {
        return res.send({ ok: false, reason: 'No password provided.' })
    }

    const count = await checkPwnedPassword(password)
    const localHit = await hasLocalPassword(password)

    if (count > 0 || localHit) {
        return res.send({ ok: false, count })
    }

    return res.send({ ok: true })
}

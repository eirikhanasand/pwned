import path from 'path'
import { execFile } from 'child_process'
import type { FastifyBaseLogger } from 'fastify'

type PasswordAuditState = {
    checkedAt: string
    ok: boolean
    report: Record<string, unknown>
} | null

let latestAudit: PasswordAuditState = null

function runValidatorScript(): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
        execFile(process.execPath, [path.join(process.cwd(), 'scripts', 'validate-password-lookups.mjs')], {
            env: process.env
        }, (error, stdout, stderr) => {
            const output = stdout || stderr
            try {
                const parsed = JSON.parse(output)
                if (error && parsed.ok !== false) {
                    reject(error)
                    return
                }

                resolve(parsed)
            } catch (parseError) {
                reject(parseError instanceof Error ? parseError : error)
            }
        })
    })
}

export async function runPasswordAudit(forceRefresh = false): Promise<PasswordAuditState> {
    const report = await runValidatorScript()
    latestAudit = {
        checkedAt: new Date().toISOString(),
        ok: report.ok === true,
        report
    }
    return latestAudit
}

export function getLatestPasswordAudit(): PasswordAuditState {
    return latestAudit
}

export function startPasswordAuditScheduler(logger: FastifyBaseLogger): void {
    void runPasswordAudit(true)
        .then(audit => logger.info({ passwordAudit: audit }, 'Password audit completed'))
        .catch(error => logger.error(error, 'Password audit failed'))

    const intervalMs = Number(process.env.PASSWORD_AUDIT_INTERVAL_MS || 15 * 60 * 1000)
    const timer = setInterval(() => {
        void runPasswordAudit(true)
            .then(audit => logger.info({ passwordAudit: audit }, 'Password audit refreshed'))
            .catch(error => logger.error(error, 'Password audit refresh failed'))
    }, intervalMs)

    timer.unref()
}

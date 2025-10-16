import crypto from 'crypto'
import packagejson from '../../package.json' with { "type": "json" }
import config from '#constants'

const { version } = packagejson

export default async function checkPassword(password: string) {
    const sha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
    const prefix = sha1.slice(0, 5)
    const suffix = sha1.slice(5)

    const response = await fetch(`${config.pwned}${prefix}`, {
        headers: { 'User-Agent': `pwnedCheck/${version} (+https://hanasand.com)` }
    })

    if (!response.ok) {
        return 0
    }

    const text = await response.text()
    const foundLine = text.split('\n').find(function(line) {
        const [h] = line.trim().split(':')
        if (h === suffix) {
            return true
        } else {
            return false
        }
    })

    if (!foundLine) {
        return 0
    }

    const parts = foundLine.split(':')
    const count = parseInt(parts[1].trim(), 10)
    if (Number.isNaN(count)) {
        return 0
    } else {
        return count
    }
}

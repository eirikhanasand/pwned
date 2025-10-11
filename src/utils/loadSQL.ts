import { readFile } from 'fs/promises'
import { join } from 'path'

export async function loadSQL(file: string) {
    const filePath = join(process.cwd(), 'src/queries', file)
    return readFile(filePath, 'utf-8')
}

import { writeFileSync, readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'

const publicModule = await import('../src/public/index.ts')
const exportKeys = Object.keys(publicModule).sort()

const snapshotPath = resolve('docs/api/public-exports.snapshot.json')
const contractPath = resolve('docs/api/public-contract.md')
const expected = existsSync(snapshotPath)
    ? (JSON.parse(readFileSync(snapshotPath, 'utf8')) as string[])
    : null

if (process.argv.includes('--write')) {
    writeFileSync(snapshotPath, `${JSON.stringify(exportKeys, null, 2)}\n`)
}

if (expected && JSON.stringify(expected) !== JSON.stringify(exportKeys)) {
    throw new Error('Public exports changed. Run: npm run test:exports:update')
}

const lines = [
    '# Public API Contract',
    '',
    '| Symbol | Kind |',
    '| --- | --- |',
    ...exportKeys.map((key) => `| \`${key}\` | export |`),
    '',
]
writeFileSync(contractPath, lines.join('\n'))

console.log(`Validated ${exportKeys.length} public exports.`)

// scripts/check-dev-env.js
import process from 'node:process'

const REQUIRED_NODE = '20.0.0'

/** @typedef {[number, number, number]} Semver */

function parseSemver(v) {
    const clean = v.replace(/^v/, '').split('-')[0]
    const parts = clean.split('.').map(Number)
    return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0]
}

function compareSemver(a, b) {
    for (let i = 0; i < 3; i++) {
        if (a[i] > b[i]) return 1
        if (a[i] < b[i]) return -1
    }
    return 0
}

function formatSemver(v) {
    return `${v[0]}.${v[1]}.${v[2]}`
}

function main() {
    const current = parseSemver(process.version)
    const required = parseSemver(REQUIRED_NODE)

    if (compareSemver(current, required) < 0) {
        console.error(`❌ Node.js ${formatSemver(current)} é muito antigo. Requerido >= ${REQUIRED_NODE}`)
        process.exit(1)
    }

    console.log(`✅ Node.js ${formatSemver(current)} (mínimo ${REQUIRED_NODE})`)
}

main()
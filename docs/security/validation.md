# Security Validation

## Local Commands

```bash
npm test
npm run test:coverage
npm run test:interop
npm run test:fuzz
npm run security:audit
```

## Focus Areas

- `test:interop`: cross-flow validation against upstream `libsignal-node`.
- `test:fuzz`: randomized/property-based robustness checks for codec and crypto surfaces.
- `test:coverage`: branch/statement regression safety net.
- `security:audit`: dependency vulnerability gate.

## CI Automation

The repository workflows execute:

- unit/integration checks on push and pull requests
- scheduled fuzz run
- CodeQL static analysis
- dependency review for PRs
- OpenSSF Scorecard scan
- npm provenance publish path (release workflow)


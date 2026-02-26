# Security Policy

## Supported Versions

Security fixes are provided for the latest `2.x` release line.

| Version | Supported |
| --- | --- |
| `2.x` | ✅ |
| `< 2.0.0` | ❌ |

## Reporting a Vulnerability

Use **GitHub Private Vulnerability Reporting** for this repository.

If private reporting is unavailable in your environment, open a confidential report with:

- Vulnerability summary
- Affected component/files
- Reproduction steps or proof of concept
- Potential impact
- Suggested mitigations (if available)

Do not open public issues for unpatched vulnerabilities.

## Response Targets

- Initial triage: within 72 hours
- Remediation plan: within 7 days after triage
- Coordinated disclosure: after fix availability

## Scope

In scope:

- Session/ratchet cryptographic flows
- Key management and identity trust checks
- Storage adapters handling sensitive material
- Worker execution and serialization boundaries

Out of scope:

- Compromised host/runtime environment
- Third-party dependency vulnerabilities without exploit path in this project


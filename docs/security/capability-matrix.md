# Capability matrix (M1)

Source of truth: `ROLE_CAPABILITIES` in `backend/aegis/security.py`. Checked server-side.

| Capability | viewer | analyst | detection_maintainer | response_proposer | response_approver | tenant_admin | auditor |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| events:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| alerts:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| rules:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| incidents:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| incidents:update | | ✓ | | | | | |
| events:ingest | | ✓ | | | | | |
| fixtures:import (local-demo only) | | ✓ | | | | ✓ | |
| audit:read | | | | | | ✓ | ✓ |

Roles `detection_maintainer`, `response_proposer`, `response_approver` exist for forward
compatibility; their write capabilities arrive with M3 (rule lifecycle) and M5 (responses).

Development users (`seed-dev`, local-demo only): `analyst@demo.local`, `viewer@demo.local`,
`auditor@demo.local`, `admin@demo.local` (tenant `tenant_demo`) and `analyst@other.local`
(tenant `tenant_other`, used for isolation tests).

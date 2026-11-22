# Capability matrix

Generated from `ROLE_CAPABILITIES` in `backend/aegis/security.py` (server-side source of truth). Every API route checks its capability; the dashboard only hides controls.

| Capability | viewer | analyst | detection_maintainer | response_proposer | response_approver | tenant_admin | auditor |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `events:ingest` |  | ✓ |  |  |  |  |  |
| `events:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `alerts:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `rules:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `incidents:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `incidents:update` |  | ✓ |  |  |  |  |  |
| `audit:read` |  |  |  |  |  | ✓ | ✓ |
| `fixtures:import` |  | ✓ |  |  |  | ✓ |  |
| `agents:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `agents:manage` |  |  |  |  |  | ✓ |  |
| `rules:write` |  |  | ✓ |  |  | ✓ |  |
| `suppressions:manage` |  | ✓ | ✓ |  |  | ✓ |  |
| `network:read` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |
| `ai:use` |  | ✓ | ✓ | ✓ |  | ✓ |  |
| `ai:audit` |  |  |  |  |  | ✓ | ✓ |
| `responses:read` |  | ✓ |  | ✓ | ✓ | ✓ | ✓ |
| `responses:propose` |  |  |  | ✓ |  |  |  |
| `responses:approve` |  |  |  |  | ✓ |  |  |
| `responses:execute` |  |  |  |  | ✓ |  |  |
| `resources:manage` |  |  |  |  |  | ✓ |  |
| `ai:policy` |  |  |  |  |  | ✓ |  |

Separation of duties: `responses:propose` and `responses:approve` are in different default
roles, and the server additionally refuses approval by the proposal's author even when one
user holds both (tested with `lead@demo.local`). AI-drafted proposals are authored by the
requesting user for this purpose.

Development identities (`seed-dev`, local-demo profile only, password from
`AEGIS_DEV_PASSWORD`): `analyst@demo.local`, `viewer@demo.local`, `auditor@demo.local`,
`admin@demo.local`, `maintainer@demo.local`, `proposer@demo.local`, `approver@demo.local`,
`lead@demo.local` (tenant `tenant_demo`) and `analyst@other.local` (tenant `tenant_other`).

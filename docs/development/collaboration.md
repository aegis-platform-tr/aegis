# Working as two developers

The directive (Section 27) suggests splitting ownership like this; decide together who is A
and who is B and write the names in the table.

| Area | Owner | Reviewer |
|---|---|---|
| Developer A: agent and collectors (`agent/`), network parsers, baselines/DDoS (`backend/aegis/baselines.py`), response adapters (`backend/aegis/responses.py`) | _A_ | _B_ |
| Developer B: AI gateway (`backend/aegis/ai/`), correlation (`correlation.py`), detection rules (`detection.py`), incidents API | _B_ | _A_ |
| Shared (pair on changes): event contract (`contracts.py` + `contracts/events/`), API contract, tenant model, migrations | both | the other |

## Branches

- `main`: always green, protected (require PR + 1 review + CI passing; no force-push).
- `develop`: integration branch for the current milestone.
- `feature/<short-name>`, `fix/<short-name>`, `docs/<short-name>` branch from `develop`.

## Rules that keep the project working

1. Run `scripts/test.sh` before opening a PR.
2. Migrations are serialized: only one open PR may add a migration at a time; never edit a
   merged migration. Contract changes include an upgrade fixture/test.
3. Security-relevant changes need a negative test (what must be refused).
4. Link the issue, ADR (if any) and test evidence in the PR description.
5. No real telemetry, credentials or personal data in the repository — fixtures are synthetic
   and use documentation address ranges.

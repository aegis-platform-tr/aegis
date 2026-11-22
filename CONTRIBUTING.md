# Contributing

Thanks for helping. AEGIS is a defensive project; contributions that add offensive capability
will be declined.

1. Open an issue describing the change before large work.
2. Branch from `main`. Keep pull requests focused.
3. Run `scripts/test.sh` locally. CI must be green (lint, `mypy --strict`, contract drift,
   tests, dashboard build, secret scan).
4. Add or update tests with every behavior change. Security-relevant changes need a negative
   test (what must be refused).
5. Changing the event contract: edit `backend/aegis/contracts.py`, run
   `python -m aegis.cli export-schema`, and bump the schema version for breaking changes
   (ADR-0001).
6. Schema changes go through a new Alembic migration; never edit an applied migration.
7. Never commit secrets, real telemetry or personal data. Fixtures must be synthetic,
   use documentation IP ranges (RFC 5737 / RFC 3849) and be labeled `"origin": "synthetic"`.

Commit messages: imperative mood, one logical change per commit.

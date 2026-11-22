# ADR-0004: Delivery and processing semantics

Status: accepted (M1)

**Ingestion.** At-least-once from producers, effectively-once storage. Uniqueness key:
`(tenant_id, producer_id, source.adapter, source.native_id)`. The event row and its
`work_items` row are inserted in one transaction; a `2xx` means both are committed. Replays
return `duplicate` with the original `event_id`; concurrent duplicates are serialized by the
unique index (`ON CONFLICT DO NOTHING`).

**Processing.** A worker claims one pending item with `FOR UPDATE SKIP LOCKED` and performs
detection, alert upsert, evidence linking, correlation and completion in the *same*
transaction. A crash rolls everything back and the item is retried; after 5 failures it is
marked `dead` with a sanitized error. Alerts are idempotent by fingerprint
`sha256(rule_id, revision, group key, window start)`; evidence links and incident links use
unique keys; incident creation is serialized per `(tenant, correlation key)` with a
transaction-scoped advisory lock.

**Time.** Rules use event time (`occurred_at`, else `observed_at`) in tumbling windows. Late
events are counted into their original window when they arrive. Collector, source and server
times are stored separately and shown separately.

**Alternatives rejected for M1.** A message broker (Kafka/NATS/Redis Streams) adds operational
cost without benefit at this scale; the outbox table can feed one later.

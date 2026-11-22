"""Per-service request-rate baselines and the DDoS anomaly signal (rule kind ``baseline``).

Measurement point: whatever sensor produced the http_request / flow events (single vantage
point). Counter semantics: one request per event; errors = HTTP 5xx or rejected/unanswered
flows. Aggregation: event-time minutes. Baseline: median and MAD of the previous
``history_minutes`` observed minutes; no seasonality model in this revision (documented).

Classification per closed minute:
  warming_up         fewer than ``warmup_minutes`` observed history minutes
  missing_telemetry  no records at all for the minute (zero traffic and a sensor gap look the
                     same from here, so it is not reported as zero)
  normal             volume score below threshold
  expected_burst     high volume, mostly from already-known sources (deployments, retries,
                     scheduled load) - recorded, never alerts
  anomaly            high volume and the new-source/surge/error conditions hold -> alert;
                     high volume that is neither clearly known nor clearly new is recorded as
                     an anomaly signal without an alert (pending corroboration)
"""

from __future__ import annotations

import statistics
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from aegis.detection import AlertOutcome, BaselineRule, active_rules, event_time, find_suppression
from aegis.models import (
    AlertEvent,
    DetectionAlert,
    DetectionRule,
    SecurityEvent,
    ServiceBaselineState,
    ServiceEvaluation,
    ServiceMinute,
    ServiceMinuteSource,
)

MAX_MINUTES_PER_PASS = 1440
MAX_EVIDENCE_PER_MINUTE = 100
ERROR_FLOW_STATES = frozenset({"REJ", "S0", "RSTO", "RSTR", "rejected"})
MINUTE = timedelta(minutes=1)


def service_key(event: SecurityEvent) -> str | None:
    if event.destination_ip is None or event.destination_port is None:
        return None
    return f"{event.destination_ip}:{event.destination_port}"


def is_error(event: SecurityEvent) -> bool:
    attrs = event.attributes or {}
    status = attrs.get("status")
    if event.event_type == "http_request" and isinstance(status, int):
        return status >= 500
    return event.event_type == "flow" and attrs.get("state") in ERROR_FLOW_STATES


def _minute(ts: datetime) -> datetime:
    return ts.replace(second=0, microsecond=0)


def process_event(session: Session, event: SecurityEvent) -> list[AlertOutcome]:
    rules = [
        (r, s)
        for r, s in active_rules(session, event.tenant_id)
        if isinstance(s, BaselineRule) and event.event_type in s.event_types
    ]
    key = service_key(event)
    if not rules or key is None:
        return []
    rule, spec = rules[0]
    assert isinstance(spec, BaselineRule)
    minute = _minute(event_time(event))
    tenant = event.tenant_id
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"baseline|{tenant}|{key}"},
    )
    session.execute(
        pg_insert(ServiceMinute)
        .values(
            tenant_id=tenant,
            service_key=key,
            minute=minute,
            requests=1,
            errors=int(is_error(event)),
            bytes=int((event.attributes or {}).get("bytes", 0) or 0),
        )
        .on_conflict_do_update(
            index_elements=["tenant_id", "service_key", "minute"],
            set_={
                "requests": ServiceMinute.requests + 1,
                "errors": ServiceMinute.errors + int(is_error(event)),
            },
        )
    )
    if event.source_ip is not None:
        session.execute(
            pg_insert(ServiceMinuteSource)
            .values(
                tenant_id=tenant,
                service_key=key,
                minute=minute,
                source_ip=str(event.source_ip),
                requests=1,
            )
            .on_conflict_do_update(
                index_elements=["tenant_id", "service_key", "minute", "source_ip"],
                set_={"requests": ServiceMinuteSource.requests + 1},
            )
        )
    state = session.get(ServiceBaselineState, (tenant, key))
    if state is None:
        state = ServiceBaselineState(
            tenant_id=tenant,
            service_key=key,
            max_seen_minute=minute,
            last_evaluated_minute=None,
            late_events=0,
        )
        session.add(state)
        session.flush()
    else:
        if state.last_evaluated_minute is not None and minute <= state.last_evaluated_minute:
            state.late_events += 1  # counted into aggregates; closed minute not re-evaluated
        if minute > state.max_seen_minute:
            state.max_seen_minute = minute
    return _evaluate_closed_minutes(session, rule, spec, state)


def _evaluate_closed_minutes(
    session: Session, rule: DetectionRule, spec: BaselineRule, state: ServiceBaselineState
) -> list[AlertOutcome]:
    last_closed = state.max_seen_minute - MINUTE * (1 + spec.grace_minutes)
    if state.last_evaluated_minute is None:
        first = session.execute(
            select(func.min(ServiceMinute.minute)).where(
                ServiceMinute.tenant_id == state.tenant_id,
                ServiceMinute.service_key == state.service_key,
            )
        ).scalar_one()
        start = first
    else:
        start = state.last_evaluated_minute + MINUTE
    outcomes: list[AlertOutcome] = []
    m, n = start, 0
    while m is not None and m <= last_closed and n < MAX_MINUTES_PER_PASS:
        outcome = _evaluate_minute(session, rule, spec, state.tenant_id, state.service_key, m)
        if outcome:
            outcomes.append(outcome)
        state.last_evaluated_minute = m
        m += MINUTE
        n += 1
    return outcomes


def _evaluate_minute(
    session: Session,
    rule: DetectionRule,
    spec: BaselineRule,
    tenant: str,
    key: str,
    minute: datetime,
) -> AlertOutcome | None:
    row = session.get(ServiceMinute, (tenant, key, minute))
    # Minutes already classified as anomalous are excluded from the baseline, so an ongoing
    # attack neither inflates the median nor makes its own sources look "known".
    anomalous = select(ServiceEvaluation.minute).where(
        ServiceEvaluation.tenant_id == tenant,
        ServiceEvaluation.service_key == key,
        ServiceEvaluation.classification == "anomaly",
    )
    history = session.execute(
        select(ServiceMinute.minute, ServiceMinute.requests).where(
            ServiceMinute.tenant_id == tenant,
            ServiceMinute.service_key == key,
            ServiceMinute.minute >= minute - MINUTE * spec.history_minutes,
            ServiceMinute.minute < minute,
            ServiceMinute.minute.not_in(anomalous),
        )
    ).all()
    record: dict[str, Any] = {
        "tenant_id": tenant,
        "service_key": key,
        "minute": minute,
        "requests": 0,
        "unique_sources": 0,
        "error_rate": Decimal(0),
    }
    if row is None:
        _save(session, record | {"classification": "missing_telemetry"})
        return None
    sources = dict(
        session.execute(
            select(ServiceMinuteSource.source_ip, ServiceMinuteSource.requests).where(
                ServiceMinuteSource.tenant_id == tenant,
                ServiceMinuteSource.service_key == key,
                ServiceMinuteSource.minute == minute,
            )
        )
        .tuples()
        .all()
    )
    record |= {
        "requests": row.requests,
        "unique_sources": len(sources),
        "error_rate": Decimal(row.errors) / row.requests,
    }
    if len(history) < spec.warmup_minutes:
        _save(session, record | {"classification": "warming_up"})
        return None

    counts = [h.requests for h in history]
    median = statistics.median(counts)
    mad = statistics.median([abs(c - median) for c in counts])
    volume_score = (row.requests - median) / (1.4826 * mad + max(1.0, 0.1 * median))
    known = {
        str(ip)
        for ip in session.execute(
            select(ServiceMinuteSource.source_ip)
            .distinct()
            .where(
                ServiceMinuteSource.tenant_id == tenant,
                ServiceMinuteSource.service_key == key,
                ServiceMinuteSource.minute >= minute - MINUTE * spec.history_minutes,
                ServiceMinuteSource.minute < minute,
                ServiceMinuteSource.minute.not_in(anomalous),
            )
        )
        .scalars()
        .all()
    }
    new_requests = sum(n for ip, n in sources.items() if str(ip) not in known)
    new_fraction = new_requests / row.requests
    hist_unique = session.execute(
        select(func.count())
        .select_from(ServiceMinuteSource)
        .where(
            ServiceMinuteSource.tenant_id == tenant,
            ServiceMinuteSource.service_key == key,
            ServiceMinuteSource.minute >= minute - MINUTE * spec.history_minutes,
            ServiceMinuteSource.minute < minute,
            ServiceMinuteSource.minute.not_in(anomalous),
        )
    ).scalar_one() / max(1, len(history))
    error_rate = float(record["error_rate"])
    record |= {
        "baseline_median": Decimal(str(round(median, 2))),
        "baseline_mad": Decimal(str(round(mad, 2))),
        "volume_score": Decimal(str(round(volume_score, 2))),
        "new_source_fraction": Decimal(str(round(new_fraction, 4))),
    }

    if volume_score < spec.volume_score_threshold:
        _save(session, record | {"classification": "normal"})
        return None
    surge = len(sources) >= spec.source_surge_ratio * max(1.0, hist_unique)
    if new_fraction >= spec.new_source_fraction_threshold and (
        surge or error_rate >= spec.error_rate_threshold
    ):
        outcome = _raise_alert(session, rule, tenant, key, minute, record, median, hist_unique)
        _save(session, record | {"classification": "anomaly", "alert_id": outcome.alert_id})
        return outcome
    if 1 - new_fraction >= spec.burst_known_source_fraction:
        _save(session, record | {"classification": "expected_burst"})
        return None
    _save(session, record | {"classification": "anomaly"})  # signal only, pending corroboration
    return None


def _save(session: Session, record: dict[str, Any]) -> None:
    session.execute(pg_insert(ServiceEvaluation).values(**record).on_conflict_do_nothing())


def _raise_alert(
    session: Session,
    rule: DetectionRule,
    tenant: str,
    key: str,
    minute: datetime,
    record: dict[str, Any],
    median: float,
    hist_unique: float,
) -> AlertOutcome:
    ip, port = key.rsplit(":", 1)
    group = {"service_key": key, "destination_ip": ip, "destination_port": port}
    prev = session.execute(
        select(ServiceEvaluation.alert_id).where(
            ServiceEvaluation.tenant_id == tenant,
            ServiceEvaluation.service_key == key,
            ServiceEvaluation.minute == minute - MINUTE,
        )
    ).scalar_one_or_none()
    if prev is None:
        from aegis.detection import fingerprint

        fp = fingerprint(rule.id, rule.revision, group, minute)
        alert_id = f"alr_{uuid.uuid4().hex}"
        session.execute(
            pg_insert(DetectionAlert)
            .values(
                id=alert_id,
                tenant_id=tenant,
                rule_id=rule.id,
                rule_revision=rule.revision,
                fingerprint=fp,
                title=f"{rule.name} ({key})",
                severity=rule.severity,
                confidence=rule.confidence,
                group_key=group,
                window_start=minute,
                window_end=minute + MINUTE,
                event_count=0,
                first_event_at=minute,
                last_event_at=minute + MINUTE,
                explanation="",
                mitre=rule.mitre,
                origin="observed",
                evidence_quality="aggregate",
            )
            .on_conflict_do_nothing(constraint="uq_alerts_fingerprint")
        )
        alert_id = session.execute(
            select(DetectionAlert.id).where(
                DetectionAlert.tenant_id == tenant, DetectionAlert.fingerprint == fp
            )
        ).scalar_one()
    else:
        alert_id = prev  # consecutive anomalous minutes extend one alert
    evidence = session.execute(
        select(SecurityEvent.id, SecurityEvent.origin)
        .where(
            SecurityEvent.tenant_id == tenant,
            SecurityEvent.destination_ip == ip,
            SecurityEvent.destination_port == int(port),
            func.coalesce(SecurityEvent.occurred_at, SecurityEvent.observed_at) >= minute,
            func.coalesce(SecurityEvent.occurred_at, SecurityEvent.observed_at) < minute + MINUTE,
        )
        .order_by(SecurityEvent.id)
        .limit(MAX_EVIDENCE_PER_MINUTE)
    ).all()
    if evidence:
        session.execute(
            pg_insert(AlertEvent)
            .values(
                [{"alert_id": alert_id, "event_id": e.id, "tenant_id": tenant} for e in evidence]
            )
            .on_conflict_do_nothing()
        )
    alert = session.get(DetectionAlert, alert_id)
    assert alert is not None
    origin = "synthetic" if any(e.origin == "synthetic" for e in evidence) else alert.origin
    count = session.execute(
        select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert_id)
    ).scalar_one()
    explanation = (
        f"Service {key}: {record['requests']} requests in minute {minute.isoformat()} vs. "
        f"baseline median {median:.1f} (volume score {record['volume_score']}); "
        f"{float(record['new_source_fraction']):.0%} of requests from sources not seen in the "
        f"previous window; {record['unique_sources']} unique sources vs. ~{hist_unique:.1f} "
        f"typical; error rate {float(record['error_rate']):.0%}. Window "
        f"[{alert.window_start.isoformat()}, {(minute + MINUTE).isoformat()}). "
        f"Low-confidence signal from a single vantage point pending corroboration; evidence "
        f"links are a sample (max {MAX_EVIDENCE_PER_MINUTE} events per minute)."
    )
    suppression = find_suppression(session, tenant, rule.id, group, {})
    values: dict[str, Any] = {
        "window_end": func.greatest(DetectionAlert.window_end, minute + MINUTE),
        "last_event_at": func.greatest(DetectionAlert.last_event_at, minute + MINUTE),
        "event_count": count,
        "explanation": explanation,
        "origin": origin,
        "updated_at": func.now(),
    }
    if suppression is not None:
        values |= {"suppressed": True, "suppression_id": suppression.id}
    session.execute(update(DetectionAlert).where(DetectionAlert.id == alert_id).values(**values))
    return AlertOutcome(alert_id, suppression is not None or bool(alert.suppressed))

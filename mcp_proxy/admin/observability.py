"""Admin observability endpoints — ADR-013 circuit breaker + detector.

Operators need a single place to answer "is the breaker shedding
right now, and what is it seeing?" without grepping logs or
instrumenting anything custom. This module exposes two endpoints:

* ``GET /v1/admin/observability/circuit-breaker`` — DB latency
  circuit breaker (ADR-013 layer 6, commit from PR #308).
* ``GET /v1/admin/observability/anomaly-detector`` — ADR-013 Phase 4
  detector: mode, current ceiling consumption, 24h quarantine count,
  etc.

Auth uses the shared ``admin_secret`` — same pattern as
``mcp_proxy/admin/info.py``.
"""
from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text

from mcp_proxy.config import get_settings

router = APIRouter(prefix="/v1/admin/observability", tags=["admin", "observability"])


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


class CircuitBreakerResponse(BaseModel):
    """Snapshot of the DB latency circuit breaker (ADR-013 layer 6).

    All latency fields are rounded milliseconds. ``None`` on a
    p99 field means the corresponding source hasn't collected
    enough samples yet (``probe_ready = false`` covers the
    composite: at least one source must be ready for the breaker
    to ever shed). Shed counters are absolute: the breaker never
    resets them at runtime, so a monitoring scrape can
    ``rate(shed_total)`` if it wants.
    """
    probe_ready: bool
    p99_ms_probe: float | None
    p99_ms_passive: float | None
    p99_ms_effective: float | None
    probe_samples_in_window: int
    passive_samples_in_window: int
    is_shedding: bool
    shed_fraction: float
    shed_count_last_60s: int
    shed_count_total: int
    activation_threshold_ms: float
    deactivation_threshold_ms: float
    max_shed_fraction: float


@router.get(
    "/circuit-breaker",
    response_model=CircuitBreakerResponse,
    dependencies=[Depends(_require_admin_secret)],
    summary="DB latency circuit breaker runtime snapshot",
)
async def get_circuit_breaker(request: Request) -> CircuitBreakerResponse:
    tracker = getattr(request.app.state, "db_latency_tracker", None)
    state = getattr(request.app.state, "db_latency_cb_state", None)

    if tracker is None or state is None:
        # The middleware/tracker haven't been wired in yet. Return a
        # deterministic "nothing configured" payload rather than 500.
        return CircuitBreakerResponse(
            probe_ready=False,
            p99_ms_probe=None,
            p99_ms_passive=None,
            p99_ms_effective=None,
            probe_samples_in_window=0,
            passive_samples_in_window=0,
            is_shedding=False,
            shed_fraction=0.0,
            shed_count_last_60s=0,
            shed_count_total=0,
            activation_threshold_ms=0.0,
            deactivation_threshold_ms=0.0,
            max_shed_fraction=0.0,
        )

    probe_p99, passive_p99, effective_p99 = tracker.p99_ms()
    probe_samples, passive_samples = tracker.sample_counts()
    probe_ready = effective_p99 is not None

    # The shed fraction the breaker would apply *right now* for a
    # request that arrived this instant. When not in the shedding
    # state the fraction is 0 regardless of p99.
    current_fraction = (
        state.shed_fraction(effective_p99)
        if state.is_shedding and effective_p99 is not None
        else 0.0
    )

    return CircuitBreakerResponse(
        probe_ready=probe_ready,
        p99_ms_probe=round(probe_p99, 1) if probe_p99 is not None else None,
        p99_ms_passive=round(passive_p99, 1) if passive_p99 is not None else None,
        p99_ms_effective=round(effective_p99, 1) if effective_p99 is not None else None,
        probe_samples_in_window=probe_samples,
        passive_samples_in_window=passive_samples,
        is_shedding=state.is_shedding,
        shed_fraction=round(current_fraction, 3),
        shed_count_last_60s=state.shed_count_last_60s(),
        shed_count_total=state.shed_total,
        activation_threshold_ms=state.activation_ms,
        deactivation_threshold_ms=state.deactivation_ms,
        max_shed_fraction=state.max_shed_fraction,
    )


# ── ADR-013 Phase 4: anomaly detector observability ────────────────


class AnomalyDetectorConfig(BaseModel):
    ratio_threshold: float
    abs_threshold_rps: float
    abs_threshold_rps_soft: float
    quarantine_ttl_hours: int
    ceiling_per_min: int
    sustained_ticks_required: int
    evaluation_interval_s: float
    baseline_min_days: int


class AnomalyDetectorResponse(BaseModel):
    """Snapshot of the anomaly detector (ADR-013 Phase 4).

    The 24h counters come from the ``agent_quarantine_events`` table
    (authoritative, survives restarts). The in-memory counters
    (``current_ceiling_consumption``, ``meta_ceiling_trips_total``,
    ``cycles_run``) are lifetime-of-process values and reset on
    restart — same convention as the circuit breaker endpoint's
    ``shed_count_total``.
    """
    mode: str  # "shadow" | "enforce" | "off"
    startup_ts: str | None
    cycles_run: int
    agents_tracked: int
    agents_with_mature_baseline: int
    quarantines_last_24h: int
    quarantines_last_24h_shadow_only: int
    quarantines_shadow_total: int
    quarantines_enforce_total: int
    meta_ceiling_trips_total: int
    current_ceiling_consumption: int
    config: AnomalyDetectorConfig


@router.get(
    "/anomaly-detector",
    response_model=AnomalyDetectorResponse,
    dependencies=[Depends(_require_admin_secret)],
    summary="Anomaly detector runtime snapshot (ADR-013 Phase 4)",
)
async def get_anomaly_detector(request: Request) -> AnomalyDetectorResponse:
    evaluator = getattr(request.app.state, "anomaly_evaluator", None)
    recorder = getattr(request.app.state, "traffic_recorder", None)
    settings = get_settings()

    # Pull 24h counts straight from the DB so the snapshot survives
    # a process restart. Two separate queries (one per mode) — cheap,
    # and each becomes its own line on a dashboard card.
    from mcp_proxy.db import _require_engine

    try:
        engine = _require_engine()
    except RuntimeError:
        engine = None

    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")

    quarantines_24h_enforce = 0
    quarantines_24h_shadow = 0
    agents_mature = 0
    if engine is not None:
        try:
            async with engine.begin() as conn:
                row_e = (
                    await conn.execute(
                        text(
                            "SELECT COUNT(*) FROM agent_quarantine_events "
                            "WHERE mode = 'enforce' AND quarantined_at >= :s"
                        ),
                        {"s": since},
                    )
                ).first()
                row_s = (
                    await conn.execute(
                        text(
                            "SELECT COUNT(*) FROM agent_quarantine_events "
                            "WHERE mode = 'shadow' AND quarantined_at >= :s"
                        ),
                        {"s": since},
                    )
                ).first()
                row_m = (
                    await conn.execute(
                        text(
                            "SELECT COUNT(DISTINCT agent_id) FROM "
                            "agent_hourly_baselines"
                        )
                    )
                ).first()
            quarantines_24h_enforce = int(row_e[0]) if row_e else 0
            quarantines_24h_shadow = int(row_s[0]) if row_s else 0
            agents_mature = int(row_m[0]) if row_m else 0
        except Exception:
            # DB reachable but query raised — return whatever else we
            # could gather (in-memory counters) rather than 500ing the
            # whole endpoint during a partial outage.
            pass

    if evaluator is None:
        # Detector not wired: fall back to "mode=off, zero activity"
        # shape so dashboards render a consistent snapshot instead of
        # erroring mid-incident. Uses settings for the config block
        # so operators still see the effective thresholds.
        cfg = AnomalyDetectorConfig(
            ratio_threshold=settings.anomaly_ratio_threshold,
            abs_threshold_rps=settings.anomaly_absolute_threshold_rps,
            abs_threshold_rps_soft=settings.anomaly_absolute_threshold_rps_soft,
            quarantine_ttl_hours=settings.anomaly_quarantine_ttl_hours,
            ceiling_per_min=settings.anomaly_ceiling_per_min,
            sustained_ticks_required=settings.anomaly_sustained_ticks_required,
            evaluation_interval_s=settings.anomaly_evaluation_interval_s,
            baseline_min_days=settings.anomaly_baseline_min_days,
        )
        return AnomalyDetectorResponse(
            mode=settings.anomaly_quarantine_mode,
            startup_ts=None,
            cycles_run=0,
            agents_tracked=recorder.agents_tracked() if recorder else 0,
            agents_with_mature_baseline=agents_mature,
            quarantines_last_24h=quarantines_24h_enforce,
            quarantines_last_24h_shadow_only=quarantines_24h_shadow,
            quarantines_shadow_total=0,
            quarantines_enforce_total=0,
            meta_ceiling_trips_total=0,
            current_ceiling_consumption=0,
            config=cfg,
        )

    cfg = AnomalyDetectorConfig(
        ratio_threshold=evaluator.ratio_threshold,
        abs_threshold_rps=evaluator.abs_threshold_rps,
        abs_threshold_rps_soft=evaluator.abs_threshold_rps_soft,
        quarantine_ttl_hours=settings.anomaly_quarantine_ttl_hours,
        ceiling_per_min=evaluator.meta_breaker.ceiling_per_min,
        sustained_ticks_required=evaluator.sustained_ticks_required,
        evaluation_interval_s=evaluator.interval_s,
        baseline_min_days=evaluator.baseline_min_days,
    )
    return AnomalyDetectorResponse(
        mode=evaluator.mode,
        startup_ts=evaluator.startup_ts,
        cycles_run=evaluator.cycles_run,
        agents_tracked=recorder.agents_tracked() if recorder else 0,
        agents_with_mature_baseline=agents_mature,
        quarantines_last_24h=quarantines_24h_enforce,
        quarantines_last_24h_shadow_only=quarantines_24h_shadow,
        quarantines_shadow_total=evaluator.quarantines_shadow_total,
        quarantines_enforce_total=evaluator.quarantines_enforce_total,
        meta_ceiling_trips_total=evaluator.meta_breaker.ceiling_trips_total,
        current_ceiling_consumption=evaluator.meta_breaker.recent_count(),
        config=cfg,
    )

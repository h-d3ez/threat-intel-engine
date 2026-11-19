import asyncio
import json
import uuid
from urllib.parse import urlparse

import httpx
import structlog

from tie.config import settings
from tie.intel.enrichment import ThreatIntelService, compute_risk_score, severity_from_risk_score
from tie.rules.engine import DetectionEngine
from tie.schemas import NormalizedEvent

logger = structlog.get_logger(__name__)
STREAM_NAME = "tie:events"
CONSUMER_GROUP = "tie-workers"


def _webhook_host(webhook_url: str) -> str:
    parsed = urlparse(webhook_url)
    return parsed.hostname or "unknown-host"


async def dispatch_webhook(webhook_url: str, fmt: str, alert_payload: dict) -> tuple[bool, int | None, str | None]:
    if not webhook_url:
        return True, None, None

    if fmt == "discord":
        body = {
            "content": (
                f"**[{alert_payload['severity'].upper()}]** {alert_payload['title']} "
                f"(Risk: {alert_payload['risk_score']}/100, MITRE: {alert_payload['mitre_technique']})"
            )
        }
    elif fmt == "slack":
        body = {
            "text": (
                f"*[{alert_payload['severity'].upper()}]* {alert_payload['title']} | "
                f"Risk: `{alert_payload['risk_score']}/100` | MITRE: `{alert_payload['mitre_technique']}`"
            )
        }
    else:
        body = alert_payload

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=body)
            ok = 200 <= resp.status_code < 300
            return ok, resp.status_code, None if ok else f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, None, str(exc)[:250]


class AlertPipeline:
    def __init__(self, db_pool, redis_client, intel_service: ThreatIntelService, rule_engine: DetectionEngine) -> None:
        self.db = db_pool
        self.redis = redis_client
        self.intel = intel_service
        self.rules = rule_engine

    async def process_event(self, event: NormalizedEvent) -> int:
        event_uuid = uuid.UUID(str(event.event_id))

        # 1. Persist normalized event idempotently
        event_row_id = await self.db.fetchval(
            """
            INSERT INTO log_events (
                event_id, timestamp, ingested_at, source, source_ip, username,
                event_type, status, http_method, http_path, http_status,
                user_agent, host, raw_log
            )
            VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING id
            """,
            event_uuid,
            event.timestamp,
            event.ingested_at,
            event.source.value,
            event.source_ip,
            event.username,
            event.event_type.value,
            event.status.value,
            event.http_method,
            event.http_path,
            event.http_status,
            event.user_agent,
            event.host,
            event.raw_log,
        )

        # If already processed, fetch existing id for evidence linkage
        if event_row_id is None:
            event_row_id = await self.db.fetchval(
                "SELECT id FROM log_events WHERE event_id = $1",
                event_uuid,
            )

        # 2. Enrich IP & run stateful rules
        intel = await self.intel.enrich_ip(event.source_ip)
        coords = (intel.latitude, intel.longitude) if (intel.latitude or intel.longitude) else None
        matches = await self.rules.evaluate(event, ip_coords=coords)

        alerts_created_or_updated = 0
        for match in matches:
            risk_score = compute_risk_score(match.rule_severity, intel.abuse_confidence, intel.is_tor)
            severity = severity_from_risk_score(risk_score)
            dedup_key = f"tie:dedup:{match.rule_id}:{match.source_ip}"

            # Atomic Redis cooldown lock across workers
            is_new_window = await self.redis.set(
                dedup_key,
                "1",
                ex=settings.alert_cooldown_seconds,
                nx=True,
            )

            if is_new_window:
                alert_id = await self.db.fetchval(
                    """
                    INSERT INTO alerts (
                        rule_id, rule_name, mitre_tactic, mitre_technique,
                        source_ip, username, severity, rule_severity,
                        abuse_confidence, risk_score, title, description, evidence
                    )
                    VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)
                    RETURNING id
                    """,
                    match.rule_id,
                    match.rule_name,
                    match.mitre_tactic,
                    match.mitre_technique,
                    match.source_ip,
                    match.username,
                    severity,
                    match.rule_severity,
                    intel.abuse_confidence,
                    risk_score,
                    match.title,
                    match.description,
                    json.dumps(match.evidence),
                )

                if settings.webhook_url:
                    ok, http_status, err = await dispatch_webhook(
                        settings.webhook_url,
                        settings.webhook_format,
                        {
                            "title": match.title,
                            "severity": severity,
                            "risk_score": risk_score,
                            "mitre_technique": match.mitre_technique,
                            "source_ip": match.source_ip,
                        },
                    )
                    await self.db.execute(
                        """
                        INSERT INTO webhook_deliveries (alert_id, target, attempt, http_status, success, error)
                        VALUES ($1, $2, 1, $3, $4, $5)
                        """,
                        alert_id,
                        _webhook_host(settings.webhook_url),
                        http_status,
                        ok,
                        err,
                    )
            else:
                # Suppressed duplicate: bump occurrence_count & last_seen on latest open alert
                alert_id = await self.db.fetchval(
                    """
                    UPDATE alerts
                    SET occurrence_count = occurrence_count + 1,
                        last_seen = now(),
                        risk_score = GREATEST(risk_score, $3)
                    WHERE id = (
                        SELECT id FROM alerts
                        WHERE rule_id = $1 AND source_ip = $2::inet
                        ORDER BY created_at DESC
                        LIMIT 1
                    )
                    RETURNING id
                    """,
                    match.rule_id,
                    match.source_ip,
                    risk_score,
                )

            if alert_id and event_row_id:
                await self.db.execute(
                    """
                    INSERT INTO alert_events (alert_id, event_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                    """,
                    alert_id,
                    event_row_id,
                )

            alerts_created_or_updated += 1

        return alerts_created_or_updated


async def run_worker_loop() -> None:
    import asyncpg
    import redis.asyncio as aioredis

    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=10)
    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)

    intel_service = ThreatIntelService(
        redis_client=redis_client,
        mode=settings.intel_mode,
        abuseipdb_api_key=settings.abuseipdb_api_key,
        cache_ttl_seconds=settings.intel_cache_ttl_seconds,
    )
    rule_engine = DetectionEngine(
        redis_client=redis_client,
        brute_force_threshold=settings.brute_force_threshold,
        brute_force_window_s=settings.brute_force_window_seconds,
        spray_distinct_users=settings.spray_distinct_users,
        spray_window_s=settings.spray_window_seconds,
        impossible_travel_max_kmh=settings.impossible_travel_max_kmh,
    )
    pipeline = AlertPipeline(pool, redis_client, intel_service, rule_engine)

    try:
        await redis_client.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass

    consumer_name = f"worker-{uuid.uuid4().hex[:8]}"
    logger.info("worker_started", consumer=consumer_name, stream=STREAM_NAME)

    try:
        while True:
            entries = await redis_client.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer_name,
                streams={STREAM_NAME: ">"},
                count=25,
                block=1000,
            )
            if not entries:
                continue

            for _, messages in entries:
                for msg_id, fields in messages:
                    raw_payload = fields.get("payload")
                    if raw_payload:
                        event = NormalizedEvent.model_validate_json(raw_payload)
                        await pipeline.process_event(event)
                    await redis_client.xack(STREAM_NAME, CONSUMER_GROUP, msg_id)
    finally:
        await redis_client.aclose()
        await pool.close()
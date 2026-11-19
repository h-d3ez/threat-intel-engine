from datetime import datetime, timezone
import fakeredis.aioredis

from tie.intel.enrichment import ThreatIntelService, compute_risk_score
from tie.rules.engine import DetectionEngine
from tie.schemas import EventStatus, EventType, LogSource, NormalizedEvent
from tie.worker.pipeline import AlertPipeline


class FakePool:
    def __init__(self) -> None:
        self.events: dict[str, int] = {}
        self.alerts: list[dict] = []
        self.deliveries: list[dict] = []
        self._next_id = 1

    async def fetchval(self, query: str, *args):
        q = " ".join(query.split()).upper()
        if "INSERT INTO LOG_EVENTS" in q:
            event_id = str(args[0])
            if event_id in self.events:
                return None
            row_id = self._next_id
            self._next_id += 1
            self.events[event_id] = row_id
            return row_id
        if "SELECT ID FROM LOG_EVENTS" in q:
            return self.events.get(str(args[0]))
        if "INSERT INTO ALERTS" in q:
            alert_id = self._next_id
            self._next_id += 1
            self.alerts.append(
                {
                    "id": alert_id,
                    "rule_id": args[0],
                    "source_ip": args[4],
                    "occurrence_count": 1,
                }
            )
            return alert_id
        if "UPDATE ALERTS" in q:
            for item in reversed(self.alerts):
                if item["rule_id"] == args[0] and item["source_ip"] == args[1]:
                    item["occurrence_count"] += 1
                    return item["id"]
            return None
        return None

    async def execute(self, query: str, *args):
        q = " ".join(query.split()).upper()
        if "INSERT INTO WEBHOOK_DELIVERIES" in q:
            self.deliveries.append({"alert_id": args[0], "target": args[1]})


async def test_intel_cache_and_dedup_increments_occurrence_count() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    db = FakePool()
    intel = ThreatIntelService(r, mode="mock", cache_ttl_seconds=3600)
    rules = DetectionEngine(r, brute_force_threshold=2, brute_force_window_s=60)
    pipeline = AlertPipeline(db, r, intel, rules)

    first_enrich = await intel.enrich_ip("203.0.113.88")
    second_enrich = await intel.enrich_ip("203.0.113.88")
    assert first_enrich == second_enrich
    assert 0 <= compute_risk_score(60, first_enrich.abuse_confidence, first_enrich.is_tor) <= 100

    # 3 failed logins exceed threshold=2 on the 3rd event -> creates 1st alert
    for i in range(3):
        ev = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source=LogSource.SSHD,
            source_ip="203.0.113.88",
            username="root",
            event_type=EventType.SSH_LOGIN,
            status=EventStatus.FAILURE,
            raw_log=f"Failed password for root from 203.0.113.88 port {5000 + i} ssh2",
        )
        await pipeline.process_event(ev)

    # 4th failed login hits Redis cooldown -> increments occurrence_count instead of creating a 2nd alert
    ev4 = NormalizedEvent(
        timestamp=datetime.now(timezone.utc),
        source=LogSource.SSHD,
        source_ip="203.0.113.88",
        username="root",
        event_type=EventType.SSH_LOGIN,
        status=EventStatus.FAILURE,
        raw_log="Failed password for root from 203.0.113.88 port 5009 ssh2",
    )
    await pipeline.process_event(ev4)

    assert len(db.alerts) == 1
    assert db.alerts[0]["occurrence_count"] == 2
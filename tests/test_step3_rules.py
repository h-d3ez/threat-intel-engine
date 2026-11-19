from datetime import datetime, timedelta, timezone
import fakeredis.aioredis

from tie.rules.engine import DetectionEngine
from tie.schemas import EventStatus, EventType, LogSource, NormalizedEvent


def _make_event(
    *,
    source: LogSource = LogSource.SSHD,
    ip: str = "203.0.113.50",
    username: str | None = "admin",
    event_type: EventType = EventType.SSH_LOGIN,
    status: EventStatus = EventStatus.FAILURE,
    ts: datetime | None = None,
    http_path: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts or datetime.now(timezone.utc),
        source=source,
        source_ip=ip,
        username=username,
        event_type=event_type,
        status=status,
        http_path=http_path,
        raw_log="test log line",
    )


async def test_brute_force_rule_triggers_after_threshold() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    engine = DetectionEngine(r, brute_force_threshold=5, brute_force_window_s=60)
    now = datetime.now(timezone.utc)

    triggered = []
    for i in range(6):
        ev = _make_event(ip="203.0.113.10", username="root", ts=now + timedelta(seconds=i))
        triggered = await engine.evaluate(ev)

    assert any(m.rule_id == "TIE-001" and m.mitre_technique == "T1110.001" for m in triggered)


async def test_password_spraying_rule_triggers() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    engine = DetectionEngine(r, spray_distinct_users=4, spray_window_s=300)
    now = datetime.now(timezone.utc)

    triggered = []
    for idx in range(5):
        ev = _make_event(ip="203.0.113.20", username=f"user{idx}", ts=now + timedelta(seconds=idx * 5))
        triggered = await engine.evaluate(ev)

    assert any(m.rule_id == "TIE-002" and m.mitre_technique == "T1110.003" for m in triggered)


async def test_impossible_travel_and_exploit_payload() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    engine = DetectionEngine(r, impossible_travel_max_kmh=900.0)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=15)

    first = _make_event(
        ip="198.51.100.1",
        username="alice",
        status=EventStatus.SUCCESS,
        ts=t0,
    )
    assert await engine.evaluate(first, ip_coords=(47.5316, 21.6273)) == []

    second = _make_event(
        ip="198.51.100.2",
        username="alice",
        status=EventStatus.SUCCESS,
        ts=t0 + timedelta(minutes=10),
    )
    travel_matches = await engine.evaluate(second, ip_coords=(40.7128, -74.0060))
    assert any(m.rule_id == "TIE-003" for m in travel_matches)

    exploit_ev = _make_event(
        source=LogSource.NGINX,
        ip="198.51.100.99",
        event_type=EventType.HTTP_REQUEST,
        status=EventStatus.FAILURE,
        http_path="/../../etc/passwd",
    )
    exploit_matches = await engine.evaluate(exploit_ev)
    assert any(m.rule_id == "TIE-004" and m.mitre_technique == "T1190" for m in exploit_matches)
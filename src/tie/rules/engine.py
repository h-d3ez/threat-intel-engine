from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math

from tie.schemas import EventStatus, EventType, NormalizedEvent


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    mitre_tactic: str
    mitre_technique: str
    rule_severity: int
    source_ip: str
    username: str | None
    title: str
    description: str
    evidence: dict


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * radius_km * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def clamp_event_time(event: NormalizedEvent, max_skew_seconds: int = 300) -> datetime:
    now = datetime.now(timezone.utc)
    ts = event.timestamp.astimezone(timezone.utc)
    if ts > now + timedelta(seconds=max_skew_seconds):
        return now
    return ts


EXPLOIT_PATTERNS = (
    "../",
    "..\\",
    "/etc/passwd",
    "union select",
    "select ",
    "<script",
    "onerror=",
    "onload=",
    "cmd=",
    "exec(",
)


class DetectionEngine:
    def __init__(
        self,
        redis_client,
        brute_force_threshold: int = 5,
        brute_force_window_s: int = 60,
        spray_distinct_users: int = 4,
        spray_window_s: int = 300,
        impossible_travel_max_kmh: float = 900.0,
    ) -> None:
        self.redis = redis_client
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window_s = brute_force_window_s
        self.spray_distinct_users = spray_distinct_users
        self.spray_window_s = spray_window_s
        self.impossible_travel_max_kmh = impossible_travel_max_kmh

    async def evaluate(
        self,
        event: NormalizedEvent,
        ip_coords: tuple[float, float] | None = None,
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        ts = clamp_event_time(event)
        ts_sec = ts.timestamp()
        event_id_str = str(event.event_id)

        # TIE-001: Brute Force (>N failed login attempts from same IP within window)
        if event.status == EventStatus.FAILURE and event.event_type in {
            EventType.SSH_LOGIN,
            EventType.WEB_LOGIN,
        }:
            bf_key = f"tie:win:bf:{event.source_ip}"
            cutoff = ts_sec - self.brute_force_window_s
            await self.redis.zremrangebyscore(bf_key, "-inf", cutoff)
            await self.redis.zadd(bf_key, {event_id_str: ts_sec})
            await self.redis.expire(bf_key, self.brute_force_window_s + 10)
            bf_count = await self.redis.zcard(bf_key)
            if bf_count > self.brute_force_threshold:
                matches.append(
                    RuleMatch(
                        rule_id="TIE-001",
                        rule_name="SSH/Login Brute Force",
                        mitre_tactic="Credential Access",
                        mitre_technique="T1110.001",
                        rule_severity=60,
                        source_ip=event.source_ip,
                        username=event.username,
                        title=f"Brute force login activity from {event.source_ip}",
                        description=(
                            f"{bf_count} failed login attempts from {event.source_ip} "
                            f"within {self.brute_force_window_s}s."
                        ),
                        evidence={"failed_attempts": bf_count, "window_s": self.brute_force_window_s},
                    )
                )

            # TIE-002: Password Spraying (>N distinct usernames from same IP within window)
            if event.username:
                spray_key = f"tie:win:spray:{event.source_ip}"
                spray_cutoff = ts_sec - self.spray_window_s
                await self.redis.zremrangebyscore(spray_key, "-inf", spray_cutoff)
                await self.redis.zadd(spray_key, {event.username: ts_sec})
                await self.redis.expire(spray_key, self.spray_window_s + 10)
                distinct_users = await self.redis.zcard(spray_key)
                if distinct_users > self.spray_distinct_users:
                    matches.append(
                        RuleMatch(
                            rule_id="TIE-002",
                            rule_name="Password Spraying",
                            mitre_tactic="Credential Access",
                            mitre_technique="T1110.003",
                            rule_severity=70,
                            source_ip=event.source_ip,
                            username=event.username,
                            title=f"Password spraying from {event.source_ip}",
                            description=(
                                f"Failed logins across {distinct_users} distinct usernames from "
                                f"{event.source_ip} within {self.spray_window_s}s."
                            ),
                            evidence={
                                "distinct_users": distinct_users,
                                "window_s": self.spray_window_s,
                            },
                        )
                    )

        # TIE-003: Impossible Travel on successful login for same user
        if (
            event.status == EventStatus.SUCCESS
            and event.username
            and event.event_type in {EventType.SSH_LOGIN, EventType.WEB_LOGIN}
            and ip_coords is not None
        ):
            travel_key = f"tie:last_login:{event.username}"
            prev_raw = await self.redis.get(travel_key)
            lat, lon = ip_coords
            current_record = {
                "ts": ts_sec,
                "ip": event.source_ip,
                "lat": lat,
                "lon": lon,
            }
            if prev_raw:
                prev = json.loads(prev_raw)
                dt_hours = (ts_sec - float(prev["ts"])) / 3600.0
                dist_km = haversine_km(
                    float(prev["lat"]), float(prev["lon"]), lat, lon
                )
                if dt_hours > 0 and dist_km > 50:
                    speed_kmh = dist_km / dt_hours
                    if speed_kmh > self.impossible_travel_max_kmh:
                        matches.append(
                            RuleMatch(
                                rule_id="TIE-003",
                                rule_name="Impossible Travel",
                                mitre_tactic="Initial Access",
                                mitre_technique="T1078",
                                rule_severity=80,
                                source_ip=event.source_ip,
                                username=event.username,
                                title=f"Impossible travel detected for user {event.username}",
                                description=(
                                    f"User {event.username} logged in from {prev['ip']} and "
                                    f"{event.source_ip} ({round(dist_km, 1)} km apart) at an implied "
                                    f"speed of {round(speed_kmh, 1)} km/h."
                                ),
                                evidence={
                                    "previous_ip": prev["ip"],
                                    "current_ip": event.source_ip,
                                    "distance_km": round(dist_km, 1),
                                    "speed_kmh": round(speed_kmh, 1),
                                },
                            )
                        )
            await self.redis.set(travel_key, json.dumps(current_record), ex=86400)

        # TIE-004: Web Exploit Payload (SQLi / XSS / Path Traversal)
        haystack = " ".join(
            part for part in (event.http_path or "", event.user_agent or "") if part
        ).lower()
        if haystack and any(pat in haystack for pat in EXPLOIT_PATTERNS):
            matches.append(
                RuleMatch(
                    rule_id="TIE-004",
                    rule_name="Web Exploit Payload (SQLi/XSS/Traversal)",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190",
                    rule_severity=75,
                    source_ip=event.source_ip,
                    username=event.username,
                    title=f"Exploit payload attempt from {event.source_ip}",
                    description=(
                        f"Suspicious web payload detected in request from {event.source_ip} "
                        f"on path {event.http_path or 'unknown'}."
                    ),
                    evidence={"http_path": event.http_path, "user_agent": event.user_agent},
                )
            )

        return matches
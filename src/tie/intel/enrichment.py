from dataclasses import dataclass
import hashlib
import ipaddress
import json

import httpx


@dataclass
class IpEnrichment:
    ip: str
    provider: str
    abuse_confidence: int
    total_reports: int
    country_code: str
    latitude: float
    longitude: float
    isp: str
    is_tor: bool = False


def compute_risk_score(rule_severity: int, abuse_confidence: int, is_tor: bool = False) -> int:
    # Weighted blend of detection rule severity and IP reputation, capped at 100
    tor_bonus = 10 if is_tor else 0
    score = round(rule_severity * 0.65 + abuse_confidence * 0.35 + tor_bonus)
    return max(0, min(100, int(score)))


def severity_from_risk_score(risk_score: int) -> str:
    if risk_score >= 85:
        return "critical"
    if risk_score >= 65:
        return "high"
    if risk_score >= 40:
        return "medium"
    return "low"


def _mock_enrich(ip: str) -> IpEnrichment:
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    # Deterministic coordinates across known global regions so impossible-travel tests work offline
    regions = [
        ("US", 40.7128, -74.0060, "Mock Cloud US"),
        ("DE", 50.1109, 8.6821, "Mock Fiber DE"),
        ("SG", 1.3521, 103.8198, "Mock Net SG"),
        ("JP", 35.6762, 139.6503, "Mock Telecom JP"),
        ("BR", -23.5505, -46.6333, "Mock Broadband BR"),
    ]
    region = regions[digest[0] % len(regions)]

    # Reserve test documentation ranges (TEST-NET-1/2/3) with higher risk for demo realism
    is_test_net = (
        ip.startswith("192.0.2.")
        or ip.startswith("198.51.100.")
        or ip.startswith("203.0.113.")
    )
    if is_test_net:
        confidence = 55 + (digest[1] % 41)  # 55..95
        reports = 10 + (digest[2] % 90)
    else:
        confidence = digest[1] % 35  # 0..34
        reports = digest[2] % 8

    is_tor = (digest[3] % 10) == 0
    return IpEnrichment(
        ip=ip,
        provider="mock",
        abuse_confidence=confidence,
        total_reports=reports,
        country_code=region[0],
        latitude=region[1],
        longitude=region[2],
        isp=region[3],
        is_tor=is_tor,
    )


class ThreatIntelService:
    def __init__(
        self,
        redis_client,
        mode: str = "mock",
        abuseipdb_api_key: str = "",
        cache_ttl_seconds: int = 86400,
    ) -> None:
        self.redis = redis_client
        self.mode = mode.lower()
        self.abuseipdb_api_key = abuseipdb_api_key
        self.cache_ttl_seconds = cache_ttl_seconds

    async def enrich_ip(self, ip: str) -> IpEnrichment:
        try:
            normalized_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return _mock_enrich(ip)

        cache_key = f"tie:intel:{self.mode}:{normalized_ip}"
        cached = await self.redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return IpEnrichment(**data)

        result = await self._fetch_provider(normalized_ip)
        await self.redis.set(
            cache_key,
            json.dumps(result.__dict__),
            ex=self.cache_ttl_seconds,
        )
        return result

    async def _fetch_provider(self, ip: str) -> IpEnrichment:
        if self.mode == "real" and self.abuseipdb_api_key:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                        headers={
                            "Key": self.abuseipdb_api_key,
                            "Accept": "application/json",
                        },
                    )
                    resp.raise_for_status()
                    payload = resp.json().get("data", {})
                    return IpEnrichment(
                        ip=ip,
                        provider="abuseipdb",
                        abuse_confidence=int(payload.get("abuseConfidenceScore", 0)),
                        total_reports=int(payload.get("totalReports", 0)),
                        country_code=str(payload.get("countryCode") or "ZZ")[:2],
                        latitude=0.0,
                        longitude=0.0,
                        isp=str(payload.get("isp") or "Unknown"),
                        is_tor=bool(payload.get("isTor", False)),
                    )
            except Exception:
                # Fall back cleanly to deterministic mock if external lookup fails
                pass

        return _mock_enrich(ip)
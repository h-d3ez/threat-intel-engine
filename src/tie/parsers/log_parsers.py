from datetime import datetime, timezone
import ipaddress
import re

from tie.schemas import EventStatus, EventType, LogSource, NormalizedEvent

SSHD_FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)

SSHD_ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)

NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+\d+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)


def _valid_ip(raw_ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw_ip.strip()))
    except ValueError:
        return None


def _parse_syslog_ts(raw_ts: str, reference_year: int | None = None) -> datetime:
    year = reference_year or datetime.now(timezone.utc).year
    dt = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def _parse_nginx_ts(raw_ts: str) -> datetime:
    dt = datetime.strptime(raw_ts.strip(), "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc)


def parse_sshd_line(line: str, reference_year: int | None = None) -> NormalizedEvent | None:
    clean_line = line.strip()[:8192]
    if not clean_line:
        return None

    for pattern, status in ((SSHD_FAILED_RE, EventStatus.FAILURE), (SSHD_ACCEPTED_RE, EventStatus.SUCCESS)):
        match = pattern.match(clean_line)
        if match:
            ip = _valid_ip(match.group("ip"))
            if not ip:
                return None
            return NormalizedEvent(
                timestamp=_parse_syslog_ts(match.group("ts"), reference_year=reference_year),
                source=LogSource.SSHD,
                source_ip=ip,
                username=match.group("username")[:256],
                event_type=EventType.SSH_LOGIN,
                status=status,
                host=match.group("host")[:255],
                raw_log=clean_line,
            )
    return None


def parse_nginx_line(line: str) -> NormalizedEvent | None:
    clean_line = line.strip()[:8192]
    if not clean_line:
        return None

    match = NGINX_RE.match(clean_line)
    if not match:
        return None

    ip = _valid_ip(match.group("ip"))
    if not ip:
        return None

    http_status = int(match.group("status"))
    user = match.group("user")
    username = None if user in {"-", ""} else user[:256]
    ua = match.group("ua")[:1024] or None

    is_login_path = "/login" in match.group("path").lower()
    event_type = EventType.WEB_LOGIN if is_login_path else EventType.HTTP_REQUEST

    if is_login_path:
        if http_status in {200, 302}:
            status = EventStatus.SUCCESS
        elif http_status in {401, 403}:
            status = EventStatus.FAILURE
        else:
            status = EventStatus.INFO
    else:
        status = EventStatus.FAILURE if http_status >= 400 else EventStatus.INFO

    return NormalizedEvent(
        timestamp=_parse_nginx_ts(match.group("ts")),
        source=LogSource.NGINX,
        source_ip=ip,
        username=username,
        event_type=event_type,
        status=status,
        http_method=match.group("method")[:16],
        http_path=match.group("path")[:4096],
        http_status=http_status,
        user_agent=ua,
        raw_log=clean_line,
    )


def parse_log_line(source: LogSource, line: str) -> NormalizedEvent | None:
    if source == LogSource.SSHD:
        return parse_sshd_line(line)
    if source == LogSource.NGINX:
        return parse_nginx_line(line)
    return None
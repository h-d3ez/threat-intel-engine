import fakeredis.aioredis
from fastapi.testclient import TestClient

from tie.api.main import STREAM_NAME, app
from tie.config import settings
from tie.parsers.log_parsers import parse_nginx_line, parse_sshd_line


def test_parse_sshd_failed_and_accepted() -> None:
    failed_line = "Nov 19 06:10:01 web-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 54112 ssh2"
    ev_fail = parse_sshd_line(failed_line, reference_year=2026)
    assert ev_fail is not None
    assert ev_fail.source_ip == "203.0.113.45"
    assert ev_fail.username == "admin"
    assert ev_fail.status == "failure"

    ok_line = "Nov 19 06:10:05 web-01 sshd[1235]: Accepted publickey for deploy from 198.51.100.10 port 54119 ssh2"
    ev_ok = parse_sshd_line(ok_line, reference_year=2026)
    assert ev_ok is not None
    assert ev_ok.status == "success"


def test_parse_nginx_traversal() -> None:
    line = '198.51.100.77 - - [19/Nov/2026:06:12:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 150 "-" "curl/8.5.0"'
    ev = parse_nginx_line(line)
    assert ev is not None
    assert ev.source_ip == "198.51.100.77"
    assert ev.http_path == "/../../etc/passwd"
    assert ev.http_status == 400
    assert ev.status == "failure"


def test_ingest_requires_api_key_and_enqueues() -> None:
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app.state.redis = fake_redis

    client = TestClient(app)
    payload = {
        "source": "sshd",
        "lines": [
            "Nov 19 06:10:01 web-01 sshd[1234]: Failed password for root from 203.0.113.45 port 54112 ssh2",
            "not a valid log line",
        ],
    }

    unauthorized = client.post("/ingest", json=payload)
    assert unauthorized.status_code == 401

    authorized = client.post(
        "/ingest",
        json=payload,
        headers={"X-API-Key": settings.ingest_api_key},
    )
    assert authorized.status_code == 200
    assert authorized.json()["accepted"] == 1
    assert authorized.json()["rejected"] == 1
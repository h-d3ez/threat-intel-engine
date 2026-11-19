import argparse
from datetime import datetime, timezone
import os
import time

import httpx


def build_attack_batches() -> list[tuple[str, list[str]]]:
    now = datetime.now(timezone.utc)
    syslog_ts = now.strftime("%b %d %H:%M:%S")
    nginx_ts = now.strftime("%d/%b/%Y:%H:%M:%S +0000")

    # 1. SSH brute-force from 203.0.113.45 (7 failed logins -> exceeds default threshold of 5)
    brute_force_lines = [
        f"{syslog_ts} edge-fw-01 sshd[2100]: Failed password for invalid user admin from 203.0.113.45 port {40000 + i} ssh2"
        for i in range(7)
    ]

    # 2. Password spraying from 198.51.100.22 across 6 distinct users (exceeds default threshold of 4)
    spray_users = ["alice", "bob", "charlie", "dana", "eve", "frank"]
    spray_lines = [
        f"{syslog_ts} edge-fw-01 sshd[2200]: Failed password for {u} from 198.51.100.22 port {41000 + idx} ssh2"
        for idx, u in enumerate(spray_users)
    ]

    # 3. Web exploit / directory traversal payload on Nginx
    nginx_lines = [
        f'192.0.2.77 - - [{nginx_ts}] "GET /../../etc/passwd HTTP/1.1" 400 182 "-" "sqlmap/1.8"',
        f'192.0.2.77 - - [{nginx_ts}] "GET /login?user=admin\' OR 1=1-- HTTP/1.1" 401 210 "-" "Mozilla/5.0"',
    ]

    return [
        ("sshd", brute_force_lines),
        ("sshd", spray_lines),
        ("nginx", nginx_lines),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate SOC log attacks against /ingest")
    parser.add_argument("--target", default="http://127.0.0.1:8000", help="Base API URL")
    parser.add_argument("--speed", type=float, default=1.0, help="Speed multiplier")
    args = parser.parse_args()

    api_key = os.environ.get("INGEST_API_KEY", "change-me-long-random-string")
    delay = max(0.05, 0.5 / max(args.speed, 0.1))

    batches = build_attack_batches()
    with httpx.Client(timeout=10.0) as client:
        for source, lines in batches:
            resp = client.post(
                f"{args.target.rstrip('/')}/ingest",
                json={"source": source, "lines": lines},
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            print(f"[{source}] sent {len(lines)} lines -> {resp.json()}")
            time.sleep(delay)


if __name__ == "__main__":
    main()
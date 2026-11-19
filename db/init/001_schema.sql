-- Threat Intelligence & Log Anomaly Engine : PostgreSQL schema (v1)
-- Runs once, on first container start, via /docker-entrypoint-initdb.d.
-- Production note: replace with versioned migrations (Alembic) in a later iteration.

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

-- ---------------------------------------------------------------- enums
CREATE TYPE event_type AS ENUM (
  'ssh_login', 'web_login', 'http_request', 'sudo', 'other'
);
CREATE TYPE event_status AS ENUM ('success', 'failure', 'info');
CREATE TYPE log_source  AS ENUM ('sshd', 'nginx', 'apache', 'syslog', 'api');
CREATE TYPE alert_severity AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE alert_status   AS ENUM ('open', 'acknowledged', 'resolved', 'false_positive');

-- ---------------------------------------------------------------- log_events
-- Normalized events. Append-only, high volume.
CREATE TABLE log_events (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id     UUID         NOT NULL DEFAULT gen_random_uuid(),
  timestamp    TIMESTAMPTZ  NOT NULL,            -- event time (from the log line)
  ingested_at  TIMESTAMPTZ  NOT NULL DEFAULT now(), -- processing time
  source       log_source   NOT NULL,
  source_ip    INET         NOT NULL,
  username     TEXT,
  event_type   event_type   NOT NULL,
  status       event_status NOT NULL,
  http_method  TEXT,
  http_path    TEXT,
  http_status  INTEGER,
  user_agent   TEXT,
  host         TEXT,
  raw_log      TEXT         NOT NULL,             -- length-capped at ingest (see parser)
  CONSTRAINT raw_log_len   CHECK (length(raw_log)   <= 8192),
  CONSTRAINT username_len  CHECK (username   IS NULL OR length(username)   <= 256),
  CONSTRAINT uagent_len    CHECK (user_agent IS NULL OR length(user_agent) <= 1024),
  CONSTRAINT path_len      CHECK (http_path  IS NULL OR length(http_path)  <= 4096),
  UNIQUE (event_id)
);
-- BRIN: tiny index, ideal for append-mostly time-ordered data.
CREATE INDEX idx_log_events_ts_brin   ON log_events USING BRIN (timestamp);
CREATE INDEX idx_log_events_ip_ts     ON log_events (source_ip, timestamp DESC);
CREATE INDEX idx_log_events_user_ts   ON log_events (username, timestamp DESC) WHERE username IS NOT NULL;

-- ---------------------------------------------------------------- ioc_enrichments
-- Threat-intel verdicts per IP/provider. Redis is the hot 24h cache; this is the durable record.
CREATE TABLE ioc_enrichments (
  id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip                INET         NOT NULL,
  provider          TEXT         NOT NULL,        -- abuseipdb | virustotal | mock
  abuse_confidence  SMALLINT     CHECK (abuse_confidence BETWEEN 0 AND 100),
  total_reports     INTEGER,
  country_code      CHAR(2),
  latitude          DOUBLE PRECISION,              -- used by impossible-travel rule
  longitude         DOUBLE PRECISION,
  isp               TEXT,
  is_tor            BOOLEAN      NOT NULL DEFAULT FALSE,
  raw_response      JSONB,
  fetched_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ  NOT NULL,         -- fetched_at + 24h (INTEL_CACHE_TTL_SECONDS)
  UNIQUE (ip, provider)
);
CREATE INDEX idx_ioc_expires ON ioc_enrichments (expires_at);

-- ---------------------------------------------------------------- alerts
CREATE TABLE alerts (
  id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  alert_uid         UUID           NOT NULL DEFAULT gen_random_uuid(),
  rule_id           TEXT           NOT NULL,       -- e.g. 'TIE-001'
  rule_name         TEXT           NOT NULL,
  mitre_tactic      TEXT           NOT NULL,       -- e.g. 'Credential Access'
  mitre_technique   TEXT           NOT NULL,       -- e.g. 'T1110.001'
  source_ip         INET           NOT NULL,
  username          TEXT,                          -- set for user-centric rules
  severity          alert_severity NOT NULL,
  rule_severity     SMALLINT       NOT NULL CHECK (rule_severity BETWEEN 0 AND 100),
  abuse_confidence  SMALLINT       CHECK (abuse_confidence BETWEEN 0 AND 100),
  risk_score        SMALLINT       NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  status            alert_status   NOT NULL DEFAULT 'open',
  title             TEXT           NOT NULL,
  description       TEXT,
  evidence          JSONB          NOT NULL DEFAULT '{}'::jsonb,
  -- dedup bookkeeping: suppressed repeats bump these instead of creating new rows
  occurrence_count  INTEGER        NOT NULL DEFAULT 1,
  first_seen        TIMESTAMPTZ    NOT NULL DEFAULT now(),
  last_seen         TIMESTAMPTZ    NOT NULL DEFAULT now(),
  created_at        TIMESTAMPTZ    NOT NULL DEFAULT now(),
  UNIQUE (alert_uid)
);
CREATE INDEX idx_alerts_status_created ON alerts (status, created_at DESC);
CREATE INDEX idx_alerts_ip_rule        ON alerts (source_ip, rule_id, last_seen DESC);
CREATE INDEX idx_alerts_risk           ON alerts (risk_score DESC);

-- ---------------------------------------------------------------- alert_events
-- Evidence trail: which normalized events triggered which alert.
CREATE TABLE alert_events (
  alert_id  BIGINT NOT NULL REFERENCES alerts(id)     ON DELETE CASCADE,
  event_id  BIGINT NOT NULL REFERENCES log_events(id) ON DELETE CASCADE,
  PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX idx_alert_events_event ON alert_events (event_id);

-- ---------------------------------------------------------------- webhook_deliveries
-- SOAR audit log + retry state. Alert creation never blocks on webhook success.
CREATE TABLE webhook_deliveries (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  alert_id      BIGINT      NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  target        TEXT        NOT NULL,              -- host only, never the full URL (it contains secrets)
  attempt       SMALLINT    NOT NULL DEFAULT 1,
  http_status   INTEGER,
  success       BOOLEAN     NOT NULL DEFAULT FALSE,
  error         TEXT,
  attempted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webhook_alert ON webhook_deliveries (alert_id);

-- ---------------------------------------------------------------- detection_rules
-- Rule metadata/config. Logic lives in code; this table makes thresholds and
-- enable/disable state runtime-tunable and visible in the dashboard.
CREATE TABLE detection_rules (
  rule_id          TEXT PRIMARY KEY,
  name             TEXT     NOT NULL,
  mitre_tactic     TEXT     NOT NULL,
  mitre_technique  TEXT     NOT NULL,
  base_severity    SMALLINT NOT NULL CHECK (base_severity BETWEEN 0 AND 100),
  enabled          BOOLEAN  NOT NULL DEFAULT TRUE,
  params           JSONB    NOT NULL DEFAULT '{}'::jsonb,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO detection_rules (rule_id, name, mitre_tactic, mitre_technique, base_severity, params) VALUES
 ('TIE-001', 'SSH/Login Brute Force',        'Credential Access', 'T1110.001', 60, '{"threshold":5,"window_s":60}'),
 ('TIE-002', 'Password Spraying',            'Credential Access', 'T1110.003', 70, '{"distinct_users":4,"window_s":300}'),
 ('TIE-003', 'Impossible Travel',            'Initial Access',    'T1078',     80, '{"max_speed_kmh":900}'),
 ('TIE-004', 'Web Exploit Payload (SQLi/XSS/Traversal)', 'Initial Access', 'T1190', 75, '{}');

-- ---------------------------------------------------------------- least-privilege app role
-- (Applied for real once the app uses a non-owner role; shown here as the target design.)
-- CREATE ROLE tie_app LOGIN PASSWORD '...';
-- GRANT SELECT, INSERT, UPDATE ON alerts, ioc_enrichments, webhook_deliveries, alert_events TO tie_app;
-- GRANT SELECT, INSERT ON log_events TO tie_app;   -- no UPDATE/DELETE: logs are append-only

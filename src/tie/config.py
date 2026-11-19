from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str = "tie"
    postgres_password: str = "change-me-postgres"
    postgres_db: str = "tie"
    database_url: str = "postgresql://tie:change-me-postgres@localhost:5432/tie"

    redis_password: str = "change-me-redis"
    redis_url: str = "redis://:change-me-redis@localhost:6379/0"

    ingest_api_key: str = "change-me-long-random-string"
    event_stream_maxlen: int = 100000
    max_raw_log_bytes: int = 8192
    max_batch_size: int = 500

    intel_mode: str = "mock"
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    intel_cache_ttl_seconds: int = 86400

    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    spray_distinct_users: int = 4
    spray_window_seconds: int = 300
    impossible_travel_max_kmh: float = 900.0

    alert_cooldown_seconds: int = 900
    webhook_url: str = ""
    webhook_format: str = "slack"

    log_level: str = "INFO"


settings = Settings()
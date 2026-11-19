from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class EventType(StrEnum):
    SSH_LOGIN = 'ssh_login'
    WEB_LOGIN = 'web_login'
    HTTP_REQUEST = 'http_request'
    SUDO = 'sudo'
    OTHER = 'other'


class EventStatus(StrEnum):
    SUCCESS = 'success'
    FAILURE = 'failure'
    INFO = 'info'


class LogSource(StrEnum):
    SSHD = 'sshd'
    NGINX = 'nginx'
    APACHE = 'apache'
    SYSLOG = 'syslog'
    API = 'api'


class NormalizedEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: LogSource
    source_ip: str
    username: str | None = Field(default=None, max_length=256)
    event_type: EventType
    status: EventStatus
    http_method: str | None = Field(default=None, max_length=16)
    http_path: str | None = Field(default=None, max_length=4096)
    http_status: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = Field(default=None, max_length=1024)
    host: str | None = Field(default=None, max_length=255)
    raw_log: str = Field(max_length=8192)

    @field_validator('timestamp', 'ingested_at')
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

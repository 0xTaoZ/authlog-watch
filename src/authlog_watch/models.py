from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEvent:
    timestamp: str
    host: str
    service: str
    event_type: str
    user: str
    source_ip: str
    port: str
    raw: str

    def to_dict(self) -> dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "service": self.service,
            "event_type": self.event_type,
            "user": self.user,
            "source_ip": self.source_ip,
            "port": self.port,
            "raw": self.raw,
        }

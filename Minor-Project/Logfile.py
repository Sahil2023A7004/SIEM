from typing import Any
from datetime import datetime, timedelta, UTC
from enum import StrEnum

from mongoengine import (
    StringField,
    DateTimeField,
    IntField,
    DictField,
    ListField,
    ObjectIdField,
)

from app.config import settings
from app.models.Base import BaseDocument


class SourceType(StrEnum):
    """
    Supported log source categories
    """
    FIREWALL = "firewall"
    IDS = "ids"
    AUTH = "auth"
    ENDPOINT = "endpoint"
    DNS = "dns"
    PROXY = "proxy"
    GENERIC = "generic"
    NETWORK = "network"


class Severity(StrEnum):
    """
    Event severity levels from critical to informational
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogEvent(BaseDocument):
    """
    Log event document with query and aggregation methods
    """
    meta: dict[str, Any] = {  # noqa: RUF012
        "collection": "log_events",
        "ordering": ["-timestamp"],
        "indexes": [
            "timestamp",
            "source_type",
            "severity",
            "source_ip",
            "dest_ip",
            "dest_port",
            "username",
            "hostname",
            "event_type",
            "ja4",
            "protocol",
            "scenario_run_id",
        ],
    }

    timestamp = DateTimeField(
        default = lambda: datetime.now(UTC),
    )
    source_type = StringField(
        required = True,
        choices = [s.value for s in SourceType],
    )
    source_ip = StringField()
    dest_ip = StringField()
    source_port = IntField()
    dest_port = IntField()
    protocol = StringField()
    tcp_flags = StringField()
    packet_size = IntField()
    ja4 = StringField()
    severity = StringField(
        choices = [s.value for s in Severity],
        default = Severity.INFO,
    )
    event_type = StringField()
    raw = DictField()
    normalized = DictField()
    metadata = DictField()
    hostname = StringField()
    username = StringField()
    mitre_tactic = StringField()
    mitre_technique = StringField()
    scenario_run_id = ObjectIdField()
    matched_alert_ids = ListField(ObjectIdField())

    @classmethod
    def create_event(cls, **fields: Any) -> "LogEvent":
        """
        Create and persist a new log event
        """
        event = cls(**fields)
        event.save()  # type: ignore[no-untyped-call]
        return event

    @classmethod
    def search(
        cls,
        query: str,
        page: int = 1,
        per_page: int = settings.DEFAULT_PAGE_SIZE
    ) -> dict[str, Any]:
        """
        Full text search across key fields including JA4 fingerprints
        """
        qs = cls.objects.filter(  # type: ignore[no-untyped-call]
            __raw__ = {
                "$or": [
                    {
                        "event_type": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                    {
                        "source_ip": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                    {
                        "dest_ip": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                    {
                        "username": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                    {
                        "hostname": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                    {
                        "ja4": {
                            "$regex": query,
                            "$options": "i"
                        }
                    },
                ]
            }
        )
        return cls.paginate(queryset = qs, page = page, per_page = per_page)

    @classmethod
    def get_by_source_ip(cls, ip: str) -> list[Any]:
        """
        Pivot query returning all events from a source IP
        """
        return list(cls.objects(source_ip = ip).order_by("-timestamp"))  # type: ignore[no-untyped-call]

    @classmethod
    def get_by_username(cls, username: str) -> list[Any]:
        """
        Pivot query returning all events for a username
        """
        return list(cls.objects(username = username).order_by("-timestamp"))  # type: ignore[no-untyped-call]

    @classmethod
    def get_by_hostname(cls, hostname: str) -> list[Any]:
        """
        Pivot query returning all events for a hostname
        """
        return list(cls.objects(hostname = hostname).order_by("-timestamp"))  # type: ignore[no-untyped-call]

    @classmethod
    def get_by_ja4(cls, ja4: str) -> list[Any]:
        """
        Pivot query returning all events matching a specific JA4 TLS fingerprint
        """
        return list(cls.objects(ja4 = ja4).order_by("-timestamp"))  # type: ignore[no-untyped-call]

    @classmethod
    def timeline_aggregation(
        cls,
        hours: int = settings.TIMELINE_DEFAULT_HOURS,
        bucket_minutes: int = settings.TIMELINE_BUCKET_MINUTES,
    ) -> list[dict[str, Any]]:
        """
        Aggregate event counts into time buckets for charting
        """
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        pipeline = [
            {
                "$match": {
                    "timestamp": {
                        "$gte": cutoff
                    }
                }
            },
            {
                "$group": {
                    "_id": {
                        "$dateTrunc": {
                            "date": "$timestamp",
                            "unit": "minute",
                            "binSize": bucket_minutes,
                        }
                    },
                    "count": {
                        "$sum": 1
                    },
                }
            },
            {
                "$sort": {
                    "_id": 1
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "bucket": "$_id",
                    "count": 1,
                }
            },
        ]
        return list(cls.objects.aggregate(pipeline))  # type: ignore[no-untyped-call]

    @classmethod
    def severity_breakdown(cls) -> list[dict[str, Any]]:
        """
        Count events grouped by severity level
        """
        pipeline = [
            {
                "$group": {
                    "_id": "$severity",
                    "count": {
                        "$sum": 1
                    },
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "severity": "$_id",
                    "count": 1,
                }
            },
        ]
        return list(cls.objects.aggregate(pipeline))  # type: ignore[no-untyped-call]

    @classmethod
    def top_sources(cls, limit: int = settings.TOP_SOURCES_LIMIT) -> list[dict[str, Any]]:
        """
        Return the most frequent source IPs
        """
        pipeline = [
            {
                "$match": {
                    "source_ip": {
                        "$ne": None
                    }
                }
            },
            {
                "$group": {
                    "_id": "$source_ip",
                    "count": {
                        "$sum": 1
                    },
                }
            },
            {
                "$sort": {
                    "count": -1
                }
            },
            {
                "$limit": limit
            },
            {
                "$project": {
                    "_id": 0,
                    "source_ip": "$_id",
                    "count": 1,
                }
            },
        ]
        return list(cls.objects.aggregate(pipeline))  # type: ignore[no-untyped-call]
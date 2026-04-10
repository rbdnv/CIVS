from datetime import UTC, datetime


def utc_now() -> datetime:
    """Returns current UTC time as naive datetime for DB compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)


def utc_now_iso() -> str:
    """Returns current UTC time as ISO string."""
    return utc_now().isoformat()

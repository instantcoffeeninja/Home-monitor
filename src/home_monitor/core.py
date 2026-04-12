"""Core helpers for Home Monitor baseline."""

from __future__ import annotations


_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


def normalize_device_name(raw_name: str) -> str:
    """Return a safe lowercase device name using only [a-z0-9_-]."""
    if not isinstance(raw_name, str):
        raise TypeError("raw_name must be a string")

    lowered = raw_name.strip().lower().replace(" ", "-")
    sanitized = "".join(ch for ch in lowered if ch in _ALLOWED_CHARS)

    if not sanitized:
        raise ValueError("device name is empty after normalization")

    return sanitized


def summarize_status(device_name: str, is_online: bool) -> dict[str, str]:
    """Build a deterministic status payload for a device."""
    normalized = normalize_device_name(device_name)
    return {
        "device": normalized,
        "status": "online" if is_online else "offline",
    }

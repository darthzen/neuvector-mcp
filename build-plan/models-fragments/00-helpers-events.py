EventKind = Literal["threat", "violation", "incident"]


def _clip(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters. Returns (text, was_truncated)."""
    if limit <= 0:
        return "", bool(text)
    if len(text) <= limit:
        return text, False
    return text[:limit], True

def count_by_level(items: list[dict[str, Any]]) -> dict[str, int]:
    """Count CIS/compliance check ``level`` values, e.g. {"PASS": 40, "WARN": 7}.

    ``level`` is a free-form string in Appendix B (``RESTBenchItem.level``); keys
    are the controller's own values, upper-cased, with "" for a missing level.
    """
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get("level", "") or "").upper()
        counts[key] = counts.get(key, 0) + 1
    return counts

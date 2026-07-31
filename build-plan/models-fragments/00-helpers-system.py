#: Sentinel meaning "the current value could not be read".
_UNKNOWN = object()


def describe_change(path: str, old: Any, new: Any) -> str:
    """One clause of a change summary: "<path> <old> -> <new>".

    ``old`` is rendered ``?`` when the current value could not be read. Values are
    rendered with ``repr`` so an empty string is visibly empty. Never pass a
    credential to this function; secrets are summarised as a field name only.
    """
    return f"{path} {'?' if old is _UNKNOWN else old!r} -> {new!r}"

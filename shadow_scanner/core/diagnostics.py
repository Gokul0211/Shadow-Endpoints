"""Errors the scanner deliberately survives (one bad file must not stop a scan).

Every such place calls swallowed(where, exc): the error is logged at DEBUG and
counted, and the counts go into the report (run.swallowed_errors), so a scan
that quietly lost half its extractors is visible instead of looking clean.
"""
import threading

from shadow_scanner.config import logger

_lock = threading.Lock()
_counts = {}      # "module" -> {"count": n, "last": "ErrorType: message"}


def swallowed(where, exc):
    with _lock:
        d = _counts.setdefault(where, {'count': 0, 'last': ''})
        d['count'] += 1
        d['last'] = f'{type(exc).__name__}: {str(exc)[:120]}'
    logger.debug(f'[swallowed] {where}: {type(exc).__name__}: {exc}')


def summary():
    with _lock:
        return {k: dict(v) for k, v in sorted(_counts.items())}


def reset():
    with _lock:
        _counts.clear()

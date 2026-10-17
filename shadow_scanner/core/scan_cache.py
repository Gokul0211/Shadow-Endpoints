"""File-backed cache of fetched JS content (enables --cache / --resume)."""
import hashlib
import json
import os
import threading
import time

from shadow_scanner.config import logger
from shadow_scanner.core import diagnostics
class ScanCache:
    """
    File-backed key-value cache for JS file content.

    Keys   : SHA-256 of the URL (avoids filesystem path issues)
    Values : dict with keys 'url', 'sha256_content', 'content', 'fetched_at'

    The cache file is a newline-delimited JSON (one entry per line) for
    append-friendly writes without loading the whole file.  On load, a
    full dict is built in memory for O(1) lookups.

    Usage:
        cache = ScanCache('scan_cache.json')
        if cache.has(url):
            code = cache.get(url)
        else:
            code = fetch(url)
            cache.put(url, code)
        cache.save()
    """

    def __init__(self, path: str = 'scan_cache.json'):
        self.path   = path
        self._store: dict[str, dict] = {}
        self._lock  = threading.Lock()
        self._dirty = False
        self._load()

    # ---------- public API ----------

    def has(self, url: str) -> bool:
        # FIX Issue 8: Only return True if content is actually available.
        # Previously, after --resume, has() returned True but get() returned None
        # because save() strips content (too large for disk). This caused silent
        # data loss — the fetch was skipped but no content was available.
        entry = self._store.get(self._key(url))
        return entry is not None and entry.get('content') is not None

    def get(self, url: str) -> str | None:
        entry = self._store.get(self._key(url))
        return entry['content'] if entry else None

    def put(self, url: str, content: str):
        key = self._key(url)
        with self._lock:
            self._store[key] = {
                'url':            url,
                'content_sha256': hashlib.sha256(content.encode()).hexdigest(),
                'content':        content,
                'fetched_at':     time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            }
            self._dirty = True

    def save(self):
        """Flush all entries to disk (safe to call from any thread)."""
        with self._lock:
            if not self._dirty:
                return
            try:
                with open(self.path, 'w', encoding='utf-8') as f:
                    for entry in self._store.values():
                        # Don't persist full content to keep cache file manageable;
                        # store content hash only — use content in memory for session.
                        line = {k: v for k, v in entry.items() if k != 'content'}
                        f.write(json.dumps(line) + '\n')
                self._dirty = False
                logger.debug(f"[Cache] Saved {len(self._store)} entries → {self.path}")
            except Exception as exc:
                logger.debug(f"[Cache] Save failed: {exc}")

    def stats(self) -> dict:
        return {'entries': len(self._store), 'path': self.path}

    # ---------- internals ----------

    @staticmethod
    def _key(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        key   = self._key(entry['url'])
                        # Content is NOT persisted (too large); mark as cache-miss
                        # so the file will be re-fetched but metadata is preserved.
                        entry.setdefault('content', None)
                        self._store[key] = entry
                    except Exception as _exc:
                        diagnostics.swallowed(__name__, _exc)
            hits = sum(1 for e in self._store.values() if e.get('content'))
            logger.debug(f"[Cache] Loaded {len(self._store)} entries from {self.path} ({hits} with content)")
        except Exception as exc:
            logger.debug(f"[Cache] Load failed: {exc}")

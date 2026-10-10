"""Phase 3: IndexedDB / Web Storage URL extraction from the running page."""
from shadow_scanner.config import is_noise, logger
# ==============================================================================
# FEATURE 3: INDEXEDDB EXTRACTOR
# ------------------------------------------------------------------------------
# Many modern SPAs persist runtime configuration - including API base URLs,
# feature flags, and cached endpoint manifests - in IndexedDB.
#
# localStorage/sessionStorage are already extracted by _extract_storage_data().
# IndexedDB requires async JS and is completely different.
#
# False-positive risk: LOW - values pass through is_noise() + _is_url_like()
# before being added as endpoints.
# ==============================================================================
class IndexedDBExtractor:
    """
    Extracts string values from all IndexedDB databases on the current page.

    UPGRADED: Now also extracts from structured objects using targeted key
    patterns (apiBase, authEndpoint, requestUrl, cacheUrl, endpoint, baseURL)
    and recursively walks nested objects/arrays with a depth-aware strategy.

    Runs as a Playwright page.evaluate() async call. Extracted values are
    filtered through the unified blocklist and URL-likeness check before
    being added as endpoints (confidence 70 - moderate, may be stale/cached).
    """

    _DUMP_SCRIPT = """
    async () => {
        const API_KEY_PATTERNS = new Set([
            'apibase','apiurl','apiendpoint','baseurl','basepath',
            'authendpoint','authurl','loginurl','tokenurl','refreshurl',
            'requesturl','cacheurl','endpoint','url','path','href',
            'graphqlurl','graphqlendpoint','wsurl','socketurl',
            'serviceurl','serviceendpoint','remoteurl','backendurl',
        ]);

        const results = [];
        const MAX_RECORDS = 1000;

        function isUrlLike(s) {
            return typeof s === 'string' && s.length >= 4 && s.length <= 500
                && (s.startsWith('/') || s.startsWith('http') || s.includes('/api/') || s.includes('/graphql'));
        }

        function collectStrings(value, out, path, depth=0) {
            if (depth > 8) return;
            if (typeof value === 'string') {
                if (isUrlLike(value)) out.push({ value, path, via: 'string' });
            } else if (Array.isArray(value)) {
                for (let i = 0; i < Math.min(value.length, 50); i++)
                    collectStrings(value[i], out, path + '[' + i + ']', depth+1);
            } else if (value && typeof value === 'object') {
                for (const [k, v] of Object.entries(value)) {
                    const kl = k.toLowerCase();
                    // Priority: if the key name matches a known API key pattern, always collect
                    if (API_KEY_PATTERNS.has(kl)) {
                        if (typeof v === 'string' && v.length >= 4)
                            out.push({ value: v, path: path + '.' + k, via: 'api_key_match' });
                    }
                    collectStrings(v, out, path + '.' + k, depth+1);
                }
            }
        }

        const dbs = await indexedDB.databases().catch(() => []);

        for (const dbInfo of dbs) {
            if (!dbInfo.name) continue;
            try {
                await new Promise((resolve) => {
                    const req = indexedDB.open(dbInfo.name, dbInfo.version);
                    req.onsuccess = (event) => {
                        const db = event.target.result;
                        const storeNames = Array.from(db.objectStoreNames);
                        let pending = storeNames.length;
                        if (pending === 0) { db.close(); resolve(); return; }

                        for (const storeName of storeNames) {
                            try {
                                const tx      = db.transaction(storeName, 'readonly');
                                const store   = tx.objectStore(storeName);
                                const getAll  = store.getAll(null, MAX_RECORDS);

                                getAll.onsuccess = () => {
                                    const records = getAll.result || [];
                                    for (const record of records) {
                                        collectStrings(record, results,
                                            dbInfo.name + '/' + storeName);
                                    }
                                    if (--pending === 0) { db.close(); resolve(); }
                                };
                                getAll.onerror = () => {
                                    if (--pending === 0) { db.close(); resolve(); }
                                };
                            } catch (_) {
                                if (--pending === 0) { db.close(); resolve(); }
                            }
                        }
                    };
                    req.onerror   = () => resolve();
                    req.onblocked = () => resolve();
                });
            } catch (_) {}
        }

        // Also scan localStorage and sessionStorage for API-key patterns
        // (belt-and-suspenders in case some apps use storage as IDB fallback)
        for (const storage of [localStorage, sessionStorage]) {
            try {
                for (let i = 0; i < storage.length; i++) {
                    const k  = storage.key(i) || '';
                    const kl = k.toLowerCase();
                    const v  = storage.getItem(k) || '';
                    if (API_KEY_PATTERNS.has(kl) && v.length >= 4)
                        results.push({ value: v, path: 'storage.' + k, via: 'storage_key_match' });
                    else if (isUrlLike(v))
                        results.push({ value: v, path: 'storage.' + k, via: 'storage_url' });
                }
            } catch (_) {}
        }

        return results;
    }
    """

    def __init__(self, base_url):
        self.base_url = base_url

    def extract_from_page(self, page, analyzer):
        """
        Dump all IDB string values, filter to URL-like candidates,
        feed survivors through add_endpoint().
        Returns count of new endpoints added.
        """
        before = len(analyzer.endpoints)

        try:
            raw_entries = page.evaluate(self._DUMP_SCRIPT)
        except Exception as exc:
            logger.debug(f"[IDB] Extraction script failed: {exc}")
            return 0

        if not raw_entries:
            logger.debug("[IDB] No IndexedDB entries found")
            return 0

        logger.debug(f"[IDB] Raw string entries: {len(raw_entries)}")

        for entry in raw_entries:
            value = entry.get('value', '')
            path  = entry.get('path', 'indexeddb')

            if is_noise(value):
                continue

            if not self._is_url_like(value):
                continue

            full_url = analyzer.normalizer.normalize(value)

            try:
                analyzer.add_endpoint(
                    full_url,
                    'GET',
                    [],
                    'INDEXEDDB_VALUE',
                    f'IndexedDB:{path}',
                    'BACKEND_API',
                    70,
                )
            except Exception as exc:
                logger.debug(f"[IDB] add_endpoint error for {value}: {exc}")

        after = len(analyzer.endpoints)
        new_eps = after - before
        if new_eps > 0:
            print(f"      [IDB] Found {new_eps} endpoints from IndexedDB")
        logger.debug(f"[IDB] {new_eps} new endpoints from {len(raw_entries)} raw entries")
        return new_eps

    @staticmethod
    def _is_url_like(value):
        """
        Stricter than EnhancedVariableResolver._is_url_like:
        require the value to look explicitly like a network path.
        """
        if len(value) < 3 or len(value) > 300:
            return False
        if value.startswith(('http://', 'https://', '/')):
            return True
        api_terms = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
                     '/service/', '/endpoint', '/rpc', '/auth/', '/data/']
        return any(t in value.lower() for t in api_terms)

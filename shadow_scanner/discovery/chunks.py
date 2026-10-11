"""Phase 1.5a/1.6: deterministic lazy-chunk discovery (webpack/Vite runtime, Next.js)."""
import re
import urllib.parse
# ==============================================================================
# WEBPACK CHUNK HARVESTER
# Deterministic lazy-chunk discovery by parsing webpack/Vite runtime bundles.
#
# Replaces fragile route-based Phase 1.6 sub-app discovery with complete
# bundle enumeration that needs zero navigation.
#
# Webpack 4 pattern:
#   script.src = __webpack_require__.p + chunkId + "." + {map}[chunkId] + ".js"
# Webpack 5 pattern:
#   __webpack_require__.u = (id) => id + "." + {103:"abc",201:"def"}[id] + ".js"
# Vite pattern: /.vite/manifest.json  or  /manifest.json
# ==============================================================================
class WebpackChunkHarvester:
    def __init__(self, session, base_url):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        _p = urllib.parse.urlparse(base_url)
        self.origin = f"{_p.scheme}://{_p.netloc}"

    # ------------------------------------------------------------------
    def harvest(self, js_files, known_urls=None):
        known     = set(known_urls or []) | set(js_files)
        discovered = set()

        print(f"\n[CHUNK HARVESTER] Scanning {len(js_files)} bundle(s) for chunk maps...")

        for fn in (self._try_vite_manifest, self._try_webpack_asset_manifest):
            hits = fn()
            if hits:
                print(f"  [+] Manifest: {len(hits)} chunk(s)")
                discovered.update(hits)

        runtime_hits = 0
        for js_url in js_files:
            try:
                r = self.session.get(js_url, timeout=15, verify=False)
                if r.status_code != 200 or len(r.text) < 800:
                    continue
                chunks = self._parse_runtime(r.text, js_url)
                new = chunks - known
                if new:
                    runtime_hits += len(new)
                    discovered.update(new)
                    known.update(new)
            except Exception:
                continue

        if runtime_hits:
            print(f"  [+] Runtime maps: {runtime_hits} chunk(s)")

        result = sorted(
            u for u in discovered
            if u not in set(known_urls or [])
            and u.endswith('.js')
            and u.startswith('http')
        )
        print(f"  [CHUNK HARVESTER] {len(result)} new bundle(s) total")
        return result

    # ------------------------------------------------------------------
    def _try_vite_manifest(self):
        found = set()
        for path in ('/.vite/manifest.json', '/manifest.json',
                     '/assets/manifest.json', '/build/manifest.json'):
            try:
                r = self.session.get(self.origin + path, timeout=6, verify=False)
                if r.status_code != 200:
                    continue
                ct = r.headers.get('content-type', '')
                if 'json' not in ct and not r.text.strip().startswith('{'):
                    continue
                data = r.json()
                for val in data.values():
                    if isinstance(val, dict):
                        f = val.get('file', '')
                        if f.endswith('.js'):
                            found.add(urllib.parse.urljoin(self.origin + '/', f.lstrip('/')))
                if found:
                    return found
            except Exception:
                continue
        return found

    def _try_webpack_asset_manifest(self):
        found = set()
        for path in ('/asset-manifest.json', '/static/asset-manifest.json',
                     '/build/asset-manifest.json'):
            try:
                r = self.session.get(self.origin + path, timeout=6, verify=False)
                if r.status_code != 200:
                    continue
                data = r.json()
                files = data.get('files', data)
                for v in files.values():
                    if isinstance(v, str) and v.endswith('.js'):
                        found.add(urllib.parse.urljoin(self.origin + '/', v.lstrip('/')))
                if found:
                    return found
            except Exception:
                continue
        return found

    # ------------------------------------------------------------------
    def _parse_runtime(self, code, source_url):
        found = set()
        if not re.search(r'__webpack_require__|webpackChunk|webpackJsonp', code):
            return found
        pub = self._extract_public_path(code, source_url)
        base = source_url.rsplit('/', 1)[0] + '/'
        found.update(self._wp5_u_fn(code, pub))
        found.update(self._wp4_script_src(code, pub))
        found.update(self._direct_filenames(code, base))
        return found

    def _extract_public_path(self, code, source_url):
        for pat in (
            r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']',
            r'publicPath\s*[=:]\s*["\']([^"\']+)["\']',
        ):
            m = re.search(pat, code)
            if m:
                p = m.group(1)
                if not p or p in ('/', ''):
                    return self.origin + '/'
                return p if p.startswith('http') else urllib.parse.urljoin(self.origin, p)
        return source_url.rsplit('/', 1)[0] + '/'

    def _wp5_u_fn(self, code, pub):
        """Webpack 5: __webpack_require__.u = function(e){ return ... }"""
        found = set()
        m = re.search(
            r'__webpack_require__\.u\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{(.{20,4000}?)\}\s*[,;]',
            code, re.DOTALL
        )
        if not m:
            # Arrow function variant
            m = re.search(
                r'__webpack_require__\.u\s*=\s*\(\s*(\w+)\s*\)\s*=>\s*\{(.{20,4000}?)\}\s*[,;]',
                code, re.DOTALL
            )
        if not m:
            return found

        param, fn_body = m.group(1), m.group(2)
        id_to_hash = {}
        id_to_name = {}

        for obj_m in re.finditer(
            r'\{((?:\s*\d+\s*:\s*["\'][^"\']*["\'],?\s*){2,})\}', fn_body
        ):
            pairs = re.findall(r'(\d+)\s*:\s*["\']([^"\']*)["\']', obj_m.group(1))
            if not pairs:
                continue
            sample = pairs[0][1]
            if re.match(r'^[a-f0-9]{5,20}$', sample) or re.match(r'^[a-zA-Z0-9_-]{5,20}$', sample):
                for cid, val in pairs:
                    id_to_hash[int(cid)] = val
            else:
                for cid, val in pairs:
                    id_to_name[int(cid)] = val

        if not id_to_hash:
            return found

        ret_m = re.search(r'return\s+(.+?);', fn_body, re.DOTALL)
        if not ret_m:
            return found

        for cid, chash in id_to_hash.items():
            try:
                fname = self._eval_tmpl(ret_m.group(1).strip(), param, cid,
                                        chash, id_to_name.get(cid, ''))
                if fname and fname.endswith('.js') and len(fname) < 120:
                    full = urllib.parse.urljoin(pub, fname)
                    if full.startswith('http'):
                        found.add(full)
            except Exception:
                continue
        return found

    def _wp4_script_src(self, code, pub):
        """Webpack 4: script.src = __webpack_require__.p + chunkId + {hash_map}[chunkId] + ".js" """
        found = set()
        # Find hash maps in the neighbourhood of script.src assignments
        for src_m in re.finditer(r'script\.src\s*=\s*__webpack_require__\.p', code):
            region = code[src_m.start(): src_m.start() + 500]
            all_maps = re.findall(
                r'\{((?:\s*["\']?\d+["\']?\s*:\s*["\'][^"\']+["\'],?\s*){2,})\}',
                region
            )
            for obj_str in all_maps:
                pairs = re.findall(r'["\']?(\d+)["\']?\s*:\s*["\']([^"\']+)["\']', obj_str)
                for cid, val in pairs:
                    # Try both common patterns
                    for tmpl in (f"{cid}.{val}.js", f"{cid}.{val}.chunk.js"):
                        full = urllib.parse.urljoin(pub, tmpl)
                        if full.startswith('http'):
                            found.add(full)
        return found

    def _direct_filenames(self, code, base):
        """Catch chunk filenames directly embedded as string literals."""
        found = set()
        for m in re.finditer(
            r'["\'](\d+\.[a-f0-9]{5,20}\.(?:chunk\.)?js)["\']', code
        ):
            found.add(urllib.parse.urljoin(base, m.group(1)))
        for m in re.finditer(
            r'["\']([a-zA-Z][a-zA-Z0-9_-]{2,40}\.[a-f0-9]{5,20}\.(?:chunk\.)?js)["\']',
            code
        ):
            fname = m.group(1)
            if any(x in fname for x in ('vendor', 'polyfill', 'runtime', 'common')):
                continue
            full = urllib.parse.urljoin(base, fname)
            if full.startswith('http') and 'localhost' not in full:
                found.add(full)
        return found

    def _eval_tmpl(self, expr, var, cid, chash, cname):
        """Minimal JS expression evaluator for webpack URL templates."""
        def _lookup(m):
            pairs = dict(re.findall(r'(\d+)\s*:\s*["\']([^"\']*)["\']', m.group(1)))
            return f'"{pairs.get(str(cid), chash)}"'

        result = re.sub(
            r'\{((?:\s*\d+\s*:\s*["\'][^"\']*["\'],?\s*){1,})\}\[' + re.escape(var) + r'\]',
            _lookup, expr
        )
        result = re.sub(
            r'\(.*?\[' + re.escape(var) + r'\]\s*\|\|\s*' + re.escape(var) + r'\)',
            f'"{cname or cid}"', result
        )
        result = re.sub(r'\b' + re.escape(var) + r'\b', str(cid), result)

        url_parts = []
        for p in re.split(r'\s*\+\s*', result):
            p = p.strip()
            if p.startswith(('"', "'")):
                url_parts.append(p.strip('"\''))
            elif p.isdigit():
                url_parts.append(p)
            elif re.match(r'^[a-zA-Z0-9_.\-]+$', p):
                url_parts.append(p)
        return ''.join(url_parts)


def _discover_nextjs_chunks(session, base_url, existing_js_files):
    """
    Next.js: find page and shared chunks the way the framework references them.

    * the build manifest (/_next/static/<buildId>/_buildManifest.js, loaded by every
      page) maps each route to its chunk files ("static/chunks/…js", relative to /_next/);
    * the webpack runtime names every other chunk in its chunk-id → name map
      ("static/chunks/" + {101: "name", …}[id] + ".js").

    Nothing is guessed by file name.
    """
    if not any('/_next/' in u for u in existing_js_files):
        return []
    base = base_url.rstrip('/')
    known = set(existing_js_files)
    discovered = []

    def add(rel):
        url = f"{base}/_next/{rel.lstrip('/')}"
        if url not in known:
            known.add(url)
            discovered.append(url)

    print("  [NEXT.JS CHUNKS] Reading the build manifest and runtime chunk map...")
    for u in list(existing_js_files):
        name = u.rsplit('/', 1)[-1].split('?')[0]
        if '/_next/' not in u or not (name.startswith('_buildManifest') or 'webpack' in name or 'runtime' in name):
            continue
        try:
            r = session.get(u, timeout=8, verify=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        text = r.text
        for rel in re.findall(r'"(static/(?:chunks|css)/[^"]+?\.js)"', text):
            add(rel)
        for prefix, mapping in re.findall(r'"(static/chunks/)"\s*\+\s*\(?\s*(\{[^{}]*\})', text):
            for chunk in re.findall(r':\s*"([^"]+)"', mapping):
                add(f"{prefix}{chunk}.js")

    print(f"    [+] {len(discovered)} chunk(s) referenced by the build manifest / runtime" if discovered
          else "    [-] No additional chunks referenced")
    return discovered

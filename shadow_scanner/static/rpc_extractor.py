"""RPC-style / string-concatenation endpoint extraction driven by the resolver."""
import re
import urllib.parse

from shadow_scanner.config import NOISE_KEYWORDS, NOISE_PATTERNS
# ==============================================================================
# CLASS: ENHANCED RPC PATTERN EXTRACTOR WITH METHOD CALL SUPPORT
# ==============================================================================
class EnhancedRPCExtractor:
    """Extracts RPC-style endpoint definitions with method call support"""

    def __init__(self, resolver):
        self.resolver = resolver
        self.endpoints = []

    def extract_rpc_patterns(self, code, filename):
        """Extract RPC concatenation patterns including method calls"""
        found = []

        # Pattern: this.property = this.method() + "path"
        pattern_method = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern_method.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            suffix = match.group(3)

            if self._is_noise(method_name, suffix):
                continue

            base_url = self.resolver.resolve_method_call(f"this.{method_name}")

            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(property_name)

                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'this.{property_name} = this.{method_name}() + "{suffix}"',
                        'key': property_name,
                        'type': 'RPC_METHOD_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 98
                    })

        # Pattern 1: Object property with concatenation (key: var + "endpoint")
        pattern1 = re.compile(r'(\w+)\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern1.finditer(code):
            key = match.group(1)
            var_name = match.group(2)
            endpoint_suffix = match.group(3)

            if self._is_noise(var_name, endpoint_suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + endpoint_suffix
                if self._is_valid_endpoint(full_endpoint):
                    method = self._guess_method_from_key(key)

                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{endpoint_suffix}"',
                        'key': key,
                        'type': 'RPC_OBJECT_PROPERTY',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })

        # Pattern 2: Variable assignment with concatenation (url = base + "path")
        pattern2 = re.compile(r'(?:var|let|const)?\s*(\w+)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern2.finditer(code):
            base_var = match.group(2)
            suffix = match.group(3)

            if self._is_noise(base_var, suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(base_var)

            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{base_var} + "{suffix}"',
                        'type': 'RPC_VARIABLE_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 90
                    })

        # Pattern 3: Template literals (`${base}path`)
        pattern3 = re.compile(r'`\$\{([a-zA-Z_$][a-zA-Z0-9_$.]*)\}([^`]+)`')
        for match in pattern3.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)

            if self._is_noise(var_name, suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'`${{{var_name}}}{suffix}`',
                        'type': 'RPC_TEMPLATE_LITERAL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })

        # Pattern 4: Method calls with concatenation
        pattern4 = re.compile(r'(?:get|post|put|delete|patch|fetch)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern4.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)

            if self._is_noise(var_name, suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + suffix
                # base + "/users/" + id  → the code itself appends a value after
                # the literal, so the path continues with a parameter segment.
                if suffix.endswith('/') and re.match(r'\s*\+\s*[A-Za-z_$(]', code[match.end():match.end() + 12]):
                    full_endpoint += '{param}'
                if self._is_valid_endpoint(full_endpoint):
                    ctx_before = code[max(0, match.start()-50):match.start()]
                    method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+20])
                    found.append({
                        'endpoint': full_endpoint,
                        'method': method,
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_HTTP_CALL',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 95
                    })

        # Pattern 5: Chained concatenation
        pattern5 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern5.finditer(code):
            var_name = match.group(1)
            part1 = match.group(2)
            part2 = match.group(3)

            if self._is_noise(var_name, part1 + part2):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + part1 + part2
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{part1}" + "{part2}"',
                        'type': 'RPC_CHAINED_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })

        # Pattern 6: Return statements
        pattern6 = re.compile(r'return\s+([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern6.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)

            if self._is_noise(var_name, suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'return {var_name} + "{suffix}"',
                        'type': 'RPC_RETURN_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 85
                    })

        # Pattern 7: Array/Object literal with concatenation
        pattern7 = re.compile(r'[\[{,]\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\']([^"\']+)["\']')
        for match in pattern7.finditer(code):
            var_name = match.group(1)
            suffix = match.group(2)

            if self._is_noise(var_name, suffix):
                continue

            base_url = self.resolver.resolve_with_fallback(var_name)

            if base_url:
                full_endpoint = base_url + suffix
                if self._is_valid_endpoint(full_endpoint):
                    found.append({
                        'endpoint': full_endpoint,
                        'method': 'GET',
                        'pattern': f'{var_name} + "{suffix}"',
                        'type': 'RPC_ARRAY_CONCAT',
                        'source': filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence': 80
                    })

        # Pattern 4b: 3-part dynamic concat (FIX BUG-3)
        # Catches: fetch(base + '/api/users/' + id + '/status', ...)
        # Pattern 4 stops at the first string literal ('/api/users/'), missing
        # the suffix that follows a dynamic parameter segment.
        # This pattern captures: base + 'prefix/' + <dynamic> + '/suffix'
        # and emits: base + prefix/{param}/suffix
        pattern4b = re.compile(
            r'(?:get|post|put|delete|patch|fetch)\s*'
            r'\(\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*\+\s*["\'`]([^"\'`]{2,80}/)["\'`]'
            r'\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$.]*'
            r'\s*\+\s*["\'`](/[^"\'`]{1,80})["\'`]',
            re.IGNORECASE
        )
        for match in pattern4b.finditer(code):
            base_var    = match.group(1)
            prefix_path = match.group(2)   # e.g. '/api/users/'
            suffix_path = match.group(3)   # e.g. '/status'
            if self._is_noise(base_var, prefix_path) or self._is_noise('', suffix_path):
                continue
            base_url = self.resolver.resolve_with_fallback(base_var)
            if base_url:
                # Reconstruct with a placeholder for the dynamic segment
                full_endpoint = (base_url.rstrip('/')
                                 + '/' + prefix_path.strip('/')
                                 + '/{param}'
                                 + suffix_path)
                if self._is_valid_endpoint(full_endpoint):
                    ctx_before = code[max(0, match.start()-50):match.start()]
                    method = self._extract_method_from_context(
                        ctx_before, code[match.start():match.start()+20])
                    found.append({
                        'endpoint':       full_endpoint,
                        'method':         method,
                        'pattern':        f'{base_var}+"{prefix_path}"+id+"{suffix_path}"',
                        'type':           'RPC_3PART_CONCAT',
                        'source':         filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence':     85,
                    })

        # Pattern 9: service-property suffix scan
        # For each service property / variable whose value is a URL base
        # (absolute, or a path ending in "/"), find every concatenation
        # this.PROP + "suffix" and `${this.PROP}suffix` in the code.
        api_service_bases = {}
        for prop_name, prop_data in sorted(self.resolver.service_properties.items()):
            base_val = prop_data.get('endpoint', '')
            if self._looks_like_base(base_val):
                api_service_bases[prop_name] = base_val

        for var_name, var_data in sorted(self.resolver.variables.items()):
            val = var_data.get('value', '') if isinstance(var_data, dict) else str(var_data)
            if not var_name.startswith('this.') or not self._looks_like_base(val):
                continue
            clean_name = var_name.replace('this.', '')
            if clean_name not in api_service_bases:
                api_service_bases[clean_name] = val

        if api_service_bases:
            for prop_name, base_url in api_service_bases.items():
                # Scan for: this.PROP + "suffix" (string concat)
                p9a = re.compile(
                    r'this\.' + re.escape(prop_name) + r'\s*\+\s*["\']([a-zA-Z]\w{2,}[^"\'<>{}\s]{0,80})["\']'
                )
                for match in p9a.finditer(code):
                    suffix = match.group(1)
                    if self._is_noise(prop_name, suffix):
                        continue
                    full_endpoint = base_url + suffix
                    if self._is_valid_endpoint(full_endpoint):
                        ctx_before = code[max(0, match.start()-60):match.start()]
                        method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+30])
                        found.append({
                            'endpoint': full_endpoint,
                            'method': method,
                            'pattern': f'this.{prop_name} + "{suffix}"',
                            'type': 'RPC_SERVICE_PROP_SUFFIX',
                            'source': filename,
                            'classification': 'RPC_ENDPOINT',
                            'confidence': 92
                        })

                # Scan for: `${this.PROP}suffix` (template literal)
                p9b = re.compile(
                    r'\$\{this\.' + re.escape(prop_name) + r'\}([a-zA-Z]\w{2,}[^`"\'<>{}\s]{0,80})'
                )
                for match in p9b.finditer(code):
                    suffix = match.group(1)
                    if self._is_noise(prop_name, suffix):
                        continue
                    full_endpoint = base_url + suffix
                    if self._is_valid_endpoint(full_endpoint):
                        ctx_before = code[max(0, match.start()-60):match.start()]
                        method = self._extract_method_from_context(ctx_before, code[match.start():match.start()+30])
                        found.append({
                            'endpoint': full_endpoint,
                            'method': method,
                            'pattern': f'${{this.{prop_name}}}{suffix}',
                            'type': 'RPC_SERVICE_PROP_SUFFIX',
                            'source': filename,
                            'classification': 'RPC_ENDPOINT',
                            'confidence': 92
                        })

        # FIX RC3-3: Pattern 10 — inline DI chain HTTP call
        # Catches: this.r.get(this.o.getBase() + "getWorkOrder")
        #          this.h.post(this.s.getUrl() + "createPermit", body)
        pattern10 = re.compile(
            r'(?:get|post|put|delete|patch)\s*\(\s*this\.'
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*'
            r'["\']([^"\']{2,80})["\']',
            re.IGNORECASE
        )
        for match in pattern10.finditer(code):
            obj_name    = match.group(1)
            method_name = match.group(2)
            suffix      = match.group(3)
            if self._is_noise(method_name, suffix):
                continue
            base_url = (
                self.resolver.resolve_method_call(f"this.{obj_name}.{method_name}")
                or self.resolver.resolve_method_call(f"this.{method_name}")
                or self.resolver.resolve_method_call(method_name)
            )
            if base_url:
                full_endpoint = base_url.rstrip('/') + '/' + suffix.lstrip('/')
                if self._is_valid_endpoint(full_endpoint):
                    ctx = code[max(0, match.start()-30):match.start()+10]
                    method = self._extract_method_from_context(ctx, '')
                    found.append({
                        'endpoint':       full_endpoint,
                        'method':         method,
                        'pattern':        f'this.{obj_name}.{method_name}() + "{suffix}"',
                        'type':           'RPC_DI_CHAIN',
                        'source':         filename,
                        'classification': 'RPC_ENDPOINT',
                        'confidence':     95
                    })

        # Pattern 11 — this.http.get/post(this.propA + this.propB, ...)
        # Catches: this.http.get(this.apiBase + this.inventoryEndpoint, {params:q})
        # where both this.propA and this.propB are string literals resolvable by resolver.
        _P11_RE = re.compile(
            r'(?:get|post|put|delete|patch)\s*\(\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\+\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)',
            re.IGNORECASE
        )
        for match in _P11_RE.finditer(code):
            prop_a = match.group(1)
            prop_b = match.group(2)
            val_a = (self.resolver.variables.get(f'this.{prop_a}', {}).get('value')
                     or self.resolver.variables.get(prop_a, {}).get('value', ''))
            val_b = (self.resolver.variables.get(f'this.{prop_b}', {}).get('value')
                     or self.resolver.variables.get(prop_b, {}).get('value', ''))
            if val_a and val_b:
                full_endpoint = str(val_a).rstrip('/') + str(val_b)
                if self._is_valid_endpoint(full_endpoint):
                    ctx = code[max(0, match.start()-30):match.start()+10]
                    method = self._extract_method_from_context(ctx, '')
                    found.append({
                        'endpoint':       full_endpoint,
                        'method':         method,
                        'pattern':        f'this.{prop_a}+this.{prop_b}',
                        'type':           'ANGULAR_SERVICE_PROP_CONCAT',
                        'source':         filename,
                        'classification': 'BACKEND_API',
                        'confidence':     92
                    })

        return found

    @staticmethod
    def _looks_like_base(value):
        """An absolute URL, or a path that ends in "/" (a base other strings are appended to)."""
        return bool(value) and (value.startswith(('http://', 'https://'))
                                or (value.startswith('/') and value.endswith('/')))

    def _is_valid_endpoint(self, endpoint):
        """Validate if endpoint looks legitimate - AGGRESSIVE FILTERING"""
        if not endpoint or len(endpoint) < 3:
            return False

        # Reject endpoints with spaces
        if ' ' in endpoint:
            return False

        # Reject template literal syntax that wasn't resolved
        if '${' in endpoint or '{{' in endpoint or '`' in endpoint:
            return False

        # Reject unbalanced parenthesis/brackets
        try:
            if endpoint.count('(') != endpoint.count(')'):
                return False
            if endpoint.count('[') != endpoint.count(']'):
                return False
            if endpoint.count('{') != endpoint.count('}'):
                return False
        except Exception:
            return False

        # Reject URLs with "undefined" or "null" literals
        if 'undefined' in endpoint.lower() or '/null' in endpoint or '/null/' in endpoint:
            return False

        # Check standard noise patterns
        for pattern in NOISE_PATTERNS:
            if re.search(pattern, endpoint, re.IGNORECASE):
                return False

        endpoint_lower = endpoint.lower()

        # Check against noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in endpoint_lower:
                return False

        # Reject Excel/internal framework paths
        if '/xl/' in endpoint_lower or 'worksheet' in endpoint_lower:
            return False

        # Reject Angular internal files
        if any(x in endpoint_lower for x in ['ngdirectivedef', 'ngpipedef', 'ngmoduledef', 'nginjectabledef', 'nginjectordef']):
            return False

        # Normalize ORIGIN placeholder
        if endpoint.startswith('ORIGIN'):
            endpoint = endpoint.replace('ORIGIN', '/')

        # Must start with a protocol or a path
        if not (endpoint.startswith('http') or endpoint.startswith('/') or endpoint.startswith('#/')):
            return False

        # Validation for http URLs
        if endpoint.startswith('http'):
            try:
                parsed = urllib.parse.urlparse(endpoint)
                if not parsed.netloc:
                    return False
                if not parsed.path or parsed.path == '/':
                    return False
                path_parts = [p for p in parsed.path.split('/') if p]
                if len(path_parts) == 1 and len(path_parts[0]) <= 2:
                    return False
            except Exception:
                return False

        # Must contain typical URL separators or patterns
        # FIX FP-2: Remove bare verbs 'get','post','fetch' from valid_indicators —
        # they match non-API strings like '/getter-utils', '/fetching-data'.
        # Only keep structural URL markers and unambiguous API keywords.
        valid_indicators = ['/', '.json', '.xml', '?', '=', '/api', '/v1', '/v2',
                            '/auth', '/user', '/admin', '/data', '/endpoint',
                            '/service', '/rest', '/graphql', '/token', '/login']
        if not any(x in endpoint_lower for x in valid_indicators):
            return False

        # Reject file extensions that aren't APIs
        if endpoint_lower.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ttf', '.eot')):
            return False

        # Reject malformed query strings
        if '?' in endpoint:
            query_part = endpoint.split('?')[1] if len(endpoint.split('?')) > 1 else ''
            if query_part and not any(c.isalnum() for c in query_part):
                return False

        return True

    def _is_noise(self, var_name, suffix):
        """Check if this is noise pattern - ULTRA STRICT"""
        combined = (var_name + suffix).lower()

        # CRITICAL: Check all noise keywords
        for keyword in NOISE_KEYWORDS:
            if keyword in combined:
                return True

        # CRITICAL: Reject if suffix is too short (likely error)
        if len(suffix) < 2:
            return True

        # CRITICAL: Reject if suffix is just special chars or spaces
        if suffix.strip() in [':', '/', '?', '=', ',', '.', '-', '_']:
            return True

        # CRITICAL: Reject error message patterns
        if any(x in combined for x in ['caused by', 'valid digit', 'error', ' dis', ' jaj', ' jar', ' lup', ' rep', ' tup']):
            return True

        # CRITICAL: Reject template syntax
        if any(x in suffix for x in ['${', '{{', '`', '\\n', '\\r']):
            return True

        # CRITICAL: Reject CSS/style fragments
        if any(x in suffix for x in ['animation-timing', 'sheet ${', 'sheet,', 'sheet[', 'sheet(', 'sheet.']):
            return True

        # CRITICAL: Reject single letter suffixes (like ' x', ' a')
        if suffix.strip() and len(suffix.strip()) == 1:
            return True

        # CRITICAL: Reject CSS units
        if suffix.strip() in ['px', 'ms', 'em', 'rem', 'vh', 'vw', 'pt', '%']:
            return True

        # CRITICAL: Reject if it's clearly a constant name, not a path
        if suffix.strip().isupper() and '_' in suffix:  # Like ON_PROPERTY
            return True

        return False

    def _guess_method_from_key(self, key):
        """Guess HTTP method from property key name"""
        k = key.lower()
        if any(x in k for x in ['get', 'fetch', 'load', 'search', 'query', 'find', 'read', 'list', 'show', 'all']):
            return 'GET'
        elif any(x in k for x in ['post', 'create', 'add', 'insert', 'new', 'submit', 'send', 'save', 'upload']):
            return 'POST'
        elif any(x in k for x in ['put', 'update', 'modify', 'edit', 'change']):
            return 'PUT'
        elif any(x in k for x in ['delete', 'remove', 'destroy', 'drop']):
            return 'DELETE'
        elif any(x in k for x in ['patch']):
            return 'PATCH'
        return 'GET'

    def _extract_method_from_context(self, before, after):
        """Extract HTTP method from surrounding context"""
        combined = (before + after).upper()

        for method in ['POST', 'PUT', 'DELETE', 'PATCH', 'GET']:
            if method in combined:
                return method

        return 'GET'

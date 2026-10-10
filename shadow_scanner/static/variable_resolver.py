"""Regex-based variable / method / service-property resolver (cross-file)."""
import hashlib
import re

from shadow_scanner.config import BASE_URL_BLACKLIST, NOISE_KEYWORDS
class EnhancedVariableResolver:
    """Resolves variables AND method calls including framework patterns"""

    def __init__(self):
        self.variables = {}
        self.global_scope = {}
        self.potential_bases = {}
        self.property_accesses = {}
        self.methods = {}
        self.service_properties = {}

        # Pre-compile regex patterns for performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for better performance"""
        self.pattern1 = re.compile(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern2 = re.compile(r'this\.(url|serverURL|baseURL|apiURL|apiUrl|rootUrl|baseUrl)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern3 = re.compile(r"this\.(url|serverURL|baseURL|apiURL)\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\[([\"'])([a-zA-Z_$][a-zA-Z0-9_$]*)\3\]")
        self.pattern4 = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern5 = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["\']([^"\']{2,100}?)["\']')
        self.pattern6 = re.compile(r'\b([a-z]{1,2})\s*=\s*["\']([^"\']{5,100}?)["\']')
        self.pattern7 = re.compile(r'(\w+)\s*:\s*["\']([^"\']{3,100}?)["\']')
        self.pattern8 = re.compile(r'["\']([/][^"\']{3,100}?)["\']\s*(?:,|])')

    def extract_all_variables(self, code, filename):
        """Extract ALL variables, methods, and service properties"""
        file_vars = {}

        # STEP 1: Extract method definitions FIRST
        self._extract_method_definitions(code, filename)

        # STEP 2: Extract service properties
        self._extract_service_properties(code, filename, file_vars)

        # STEP 3: Extract regular variable patterns using pre-compiled patterns

        # Pattern 1: var/let/const declarations
        for match in self.pattern1.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 90)

        # Pattern 2: this.url = ... or this.serverURL = ...
        for match in self.pattern2.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 98)
                self._register_variable(prop, var_value, filename, file_vars, 95)
                self.property_accesses[prop] = var_value

        # Pattern 3: this.url = someObj.serverURL or this.url = config.url
        for match in self.pattern3.finditer(code):
            prop = match.group(1)
            source_obj = match.group(2)
            source_prop = match.group(4)
            self.property_accesses[prop] = f"{source_obj}.{source_prop}"

        # Pattern 4: Object property assignments (this.prop = value)
        for match in self.pattern4.finditer(code):
            prop = match.group(1)
            var_value = match.group(2)
            if not self._is_noise_value(var_value):
                self._register_variable(f"this.{prop}", var_value, filename, file_vars, 95)
                self._register_variable(prop, var_value, filename, file_vars, 90)
                self.property_accesses[prop] = var_value

        # Pattern 5: Simple assignments
        for match in self.pattern5.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if var_name not in file_vars and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 70)

        # FIX EP-B-003: Pattern 2b — resolve this.X = this.Y + this.Z
        # Handles: this.odataBase = this.apiBase + this.inventoryEndpoint
        # where this.apiBase="http://localhost:3002" and this.inventoryEndpoint="/api/inventory/items"
        # are already registered in file_vars / this.variables
        _THIS_CONCAT_RE = re.compile(
            r'this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\+\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)'
        )
        for mc in _THIS_CONCAT_RE.finditer(code):
            dest, src1, src2 = mc.group(1), mc.group(2), mc.group(3)
            # Resolve src1 and src2 from already-registered variables
            val1 = (file_vars.get(f'this.{src1}') or file_vars.get(src1) or
                    self.variables.get(f'this.{src1}', {}).get('value') or
                    self.variables.get(src1, {}).get('value') or '')
            val2 = (file_vars.get(f'this.{src2}') or file_vars.get(src2) or
                    self.variables.get(f'this.{src2}', {}).get('value') or
                    self.variables.get(src2, {}).get('value') or '')
            if val1 and val2:
                combined = str(val1) + str(val2)
                if not self._is_noise_value(combined):
                    self._register_variable(f'this.{dest}', combined, filename, file_vars, 95)
                    self._register_variable(dest, combined, filename, file_vars, 92)
                    self.property_accesses[dest] = combined

        # Pattern 6: Minified variable assignments (single/double letter)
        for match in self.pattern6.finditer(code):
            var_name = match.group(1)
            var_value = match.group(2)
            if self._is_url_like(var_value) and not self._is_noise_value(var_value):
                self._register_variable(var_name, var_value, filename, file_vars, 60)

        # Pattern 7: Object literal properties
        for match in self.pattern7.finditer(code):
            key = match.group(1)
            value = match.group(2)
            if self._is_url_like(value) and not self._is_noise_value(value):
                self._register_variable(key, value, filename, file_vars, 65)

        # Pattern 8: Array items that look like URLs (FIXED - using hash instead of truncation)
        for match in self.pattern8.finditer(code):
            val = match.group(1)
            if self._is_url_like(val) and not self._is_noise_value(val):
                # FIXED: Use hash to avoid key collisions
                val_hash = hashlib.md5(val.encode()).hexdigest()[:8]
                self._register_variable(f"ARRAY_ITEM_{val_hash}", val, filename, file_vars, 60)

        # ── P1 FIX: Object property path registration ─────────────────────
        # Registers dotted paths like cfg.method, VERSIONS.prod, api.baseUrl
        # so they resolve in template literals and computed property keys.
        #
        # Handles:
        #   const cfg = { method: 'get', base: '/api' }  → cfg.method='get', cfg.base='/api'
        #   const VERSIONS = { prod: 'v2', dev: 'v1' }   → VERSIONS.prod='v2'
        #   const routes = { users: '/api/users' }        → routes.users='/api/users'
        _OBJ_INIT_RE = re.compile(
            r'(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{([^{}]{1,3000})\}',
            re.DOTALL
        )
        for obj_m in _OBJ_INIT_RE.finditer(code):
            obj_name = obj_m.group(1)
            obj_body = obj_m.group(2)

            # Extract key: "string_value" pairs
            # Supports BOTH unquoted keys (method: 'get') AND quoted keys ('read': 'get')
            for prop_m in re.finditer(
                r'(?:^|,)\s*(?:[\'"`]([^\'"`]{1,100})[\'"`]|([A-Za-z_$][A-Za-z0-9_$]*))\s*:\s*[\'"`]([^\'"`]{1,300})[\'"`]',
                obj_body
            ):
                key = prop_m.group(1) or prop_m.group(2)   # quoted OR unquoted key
                val = prop_m.group(3)
                if not key:
                    continue
                dotted = f'{obj_name}.{key}'
                self.global_scope[dotted]  = val
                self.variables[dotted]     = {'value': val, 'source_file': filename, 'confidence': 90}
                # Also register short key if it looks like a URL fragment
                if self._is_url_like(val):
                    self._register_variable(dotted, val, filename, file_vars, 90)

            # Extract key: variable_reference pairs (indirect)
            # Supports both quoted and unquoted keys
            for prop_m in re.finditer(
                r'(?:^|,)\s*(?:[\'"`]([^\'"`]{1,100})[\'"`]|([A-Za-z_$][A-Za-z0-9_$]*))\s*:\s*([A-Za-z_$][A-Za-z0-9_$.]+)(?:\s*[,}\n])',
                obj_body
            ):
                key = prop_m.group(1) or prop_m.group(2)
                ref = prop_m.group(3)
                if not key or ref in ('true', 'false', 'null', 'undefined'):
                    continue
                resolved = (self.global_scope.get(ref)
                            or (self.variables.get(ref) or {}).get('value')
                            or self.resolve_with_fallback(ref))
                if resolved and isinstance(resolved, str):
                    dotted = f'{obj_name}.{key}'
                    self.global_scope[dotted] = resolved
                    self.variables[dotted]    = {'value': resolved, 'source_file': filename, 'confidence': 85}
                    if self._is_url_like(resolved):
                        self._register_variable(dotted, resolved, filename, file_vars, 85)

        # ── P1 FIX: Array element registration ────────────────────────────
        # Registers arr[0], arr[1] as "arr.0", "arr.1" keys so template
        # literals like `${arr[0]}` resolve to the actual element value.
        #
        # Handles:
        #   const versions = ['v1', 'v2']  → versions.0='v1', versions.1='v2'
        #   const paths = ['/api/a', '/api/b']  → paths.0='/api/a'
        _ARR_INIT_RE = re.compile(
            r'(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[([^\]]{1,1000})\]'
        )
        for arr_m in _ARR_INIT_RE.finditer(code):
            arr_name = arr_m.group(1)
            elements_raw = arr_m.group(2)
            # Split by comma — handle quoted strings (no regex for balanced parens needed here)
            elements = re.findall(r'[\'"`]([^\'"`]{1,200})[\'"`]', elements_raw)
            for i, elem in enumerate(elements):
                if elem:
                    idx_key = f'{arr_name}.{i}'
                    self.global_scope[idx_key] = elem
                    self.variables[idx_key]    = {'value': elem, 'source_file': filename, 'confidence': 88}

        return file_vars

    def _extract_method_definitions(self, code, filename):
        """Extract method definitions and their return values"""
        # Pattern 1: methodName(){return "value"} - Made more flexible to handle nested braces
        pattern1 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern1.finditer(code):
            method_name = match.group(1)
            return_value = match.group(2)
            if self._is_url_like(return_value):
                self.methods[method_name] = return_value
                self.methods[f"this.{method_name}"] = return_value

        # Pattern 2: methodName(){return condition ? "val1" : "val2"}
        pattern2 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return[^}]+\?[^:]+:(?:[^}]|\{[^}]*\})*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern2.finditer(code):
            method_name = match.group(1)
            # Extract all string literals from the ternary
            ternary_section = code[match.start():match.end()]
            strings = re.findall(r'["\']([^"\']+)["\']', ternary_section)
            for s in strings:
                if self._is_url_like(s):
                    self.methods[method_name] = s
                    self.methods[f"this.{method_name}"] = s
                    break

        # Pattern 3: methodName(){...return location.origin + "/api"}
        pattern3 = re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\{(?:[^{}]|\{[^}]*\})*return\s+location\.origin\s*\+\s*["\']([^"\']+)["\']', re.DOTALL)
        for match in pattern3.finditer(code):
            method_name = match.group(1)
            suffix = match.group(2)
            # Store as a pattern that needs base URL resolution
            self.methods[method_name] = f"ORIGIN{suffix}"
            self.methods[f"this.{method_name}"] = f"ORIGIN{suffix}"

        # FIX RC3-2: Pattern 5 — register methods that return this.obj.prop
        # [^{]* handles TypeScript return type annotations like `: string {`
        pattern5 = re.compile(
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)[^{]*\{'
            r'[^}]*return\s+this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)',
            re.DOTALL
        )
        for match in pattern5.finditer(code):
            method_name = match.group(1)
            obj_ref     = match.group(2)
            prop_ref    = match.group(3)
            resolved_val = (
                self.variables.get(f"this.{obj_ref}", {}).get('value')
                or self.variables.get(obj_ref, {}).get('value')
                or self.property_accesses.get(prop_ref)
                or self.property_accesses.get(f"{obj_ref}.{prop_ref}")
            )
            if resolved_val and self._is_url_like(resolved_val):
                self.methods[method_name]           = resolved_val
                self.methods[f"this.{method_name}"] = resolved_val

        # prototype syntax — minified Angular bundles use this form
        # [^{]* handles TypeScript type annotations between ) and {
        pattern_proto = re.compile(
            r'(?:prototype|__proto__)\.'
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\([^)]*\)[^{]*\{'
            r'[^}]*return\s+this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)',
            re.DOTALL
        )
        for match in pattern_proto.finditer(code):
            method_name = match.group(1)
            obj_ref, prop_ref = match.group(2), match.group(3)
            resolved_val = (
                self.variables.get(f"this.{obj_ref}", {}).get('value')
                or self.variables.get(obj_ref, {}).get('value')
                or self.property_accesses.get(prop_ref)
                or self.property_accesses.get(f"{obj_ref}.{prop_ref}")
            )
            if resolved_val and self._is_url_like(resolved_val):
                self.methods[method_name] = resolved_val
                self.methods[f"this.{method_name}"] = resolved_val

        # Pattern 4: Environment object support — expanded keyword list
        # catches stagingApiUrl, oauthTokenEndpoint, apiBaseUrl, internalServiceUrl etc.
        # Priority: apiBaseUrl/apiUrl/backendUrl first, others as secondary.
        _ENV_PRIMARY_KEYS = re.compile(
            r'\b(apiBaseUrl|apiUrl|backendUrl|serviceUrl|serverUrl|apiEndpoint'
            r'|remoteServiceUrl|wsUrl|wsEndpoint|socketUrl|graphqlEndpoint|graphqlUrl)\b',
            re.IGNORECASE
        )
        # First pass: register all env keys under their own names in global_scope
        _all_env_pattern = re.compile(
            r'(apiBaseUrl|apiUrl|backendUrl|serviceUrl|serverUrl|apiEndpoint'
            r'|stagingApiUrl|oauthTokenEndpoint|tokenEndpoint|authEndpoint'
            r'|internalServiceUrl|remoteServiceUrl|wsUrl|wsEndpoint'
            r'|socketUrl|graphqlEndpoint|graphqlUrl)\s*:\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        _primary_env_url = None
        for match in _all_env_pattern.finditer(code):
            key_name = match.group(1)
            url = match.group(2)
            if self._is_url_like(url):
                self._register_variable(key_name, url, filename, {}, 95)
                self._register_variable(f"environment.{key_name}", url, filename, {}, 95)
                self.global_scope[key_name] = url
                self.global_scope[f"environment.{key_name}"] = url
                # Register getApiBase / getBase methods to return the primary URL
                if _ENV_PRIMARY_KEYS.match(key_name) and _primary_env_url is None:
                    _primary_env_url = url
                    self.methods['environmentApiUrl'] = url
                    self.methods['getApiBase']  = url
                    self.methods['getBase']     = url
                    self.methods['getApiUrl']   = url
                    self.methods['getRootUrl']  = url
                    self.methods['getUrl']      = url
                    self.methods['this.getApiBase']  = url
                    self.methods['this.getBase']     = url
                    self.methods['this.getApiUrl']   = url
                    self.methods['this.getRootUrl']  = url

        # FIX RC3-2: Pattern 5 (second pass) — catches methods seen before their
        # returned property was registered (multi-file / multi-threaded ordering).
        # [^{]* handles TypeScript return type annotations like `: string {`
        pattern5b = re.compile(
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)[^{]*\{'
            r'[^}]*return\s+this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)',
            re.DOTALL
        )
        for match in pattern5b.finditer(code):
            method_name = match.group(1)
            obj_ref     = match.group(2)
            prop_ref    = match.group(3)
            resolved_val = (
                self.variables.get(f"this.{obj_ref}", {}).get('value')
                or self.variables.get(obj_ref, {}).get('value')
                or self.property_accesses.get(prop_ref)
                or self.property_accesses.get(f"{obj_ref}.{prop_ref}")
            )
            if resolved_val and self._is_url_like(resolved_val):
                self.methods[method_name]           = resolved_val
                self.methods[f"this.{method_name}"] = resolved_val

        # Second-pass resolution: re-check methods whose value is not yet a URL.
        # Needed when getBase() is parsed before AppConfigService's property
        # is registered (non-deterministic multi-file processing order).
        for _mn in list(self.methods.keys()):
            _mv = self.methods[_mn]
            if _mv and not _mv.startswith('http') and not _mv.startswith('/'):
                _resolved2 = (
                    self.resolve_with_fallback(_mv)
                    or self.property_accesses.get(_mv)
                )
                if _resolved2 and self._is_url_like(_resolved2):
                    self.methods[_mn] = _resolved2

    def _extract_service_properties(self, code, filename, file_vars):
        """Extract service property patterns like this.propertyName=this.methodCall()+'/path'"""
        # Pattern: this.propertyName = this.methodCall() + "/path"
        pattern = re.compile(r'this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*this\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(\s*\)\s*\+\s*["\']([^"\']+)["\']')

        for match in pattern.finditer(code):
            property_name = match.group(1)
            method_name = match.group(2)
            path_suffix = match.group(3)

            # Try to resolve the method
            method_result = self._resolve_method(method_name)

            if method_result:
                # Combine method result with suffix
                full_endpoint = method_result + path_suffix

                # Register as a service property
                self.service_properties[property_name] = {
                    'endpoint': full_endpoint,
                    'method_call': f"this.{method_name}()",
                    'suffix': path_suffix,
                    'source': filename
                }

                # Also register as a regular variable
                self._register_variable(property_name, full_endpoint, filename, file_vars, 95)
                self._register_variable(f"this.{property_name}", full_endpoint, filename, file_vars, 98)

    def _resolve_method(self, method_name):
        """Resolve a method call to its return value"""
        # Check direct method name
        if method_name in self.methods:
            return self.methods[method_name]

        # Check with this. prefix
        if f"this.{method_name}" in self.methods:
            return self.methods[f"this.{method_name}"]

        # Common method names that return API base URLs
        common_methods = {
            'getRootUrl': '/api',
            'getBaseUrl': '/api',
            'getApiUrl': '/api',
            'getServerUrl': '/api',
            'getApiBaseUrl': '/api'
        }

        if method_name in common_methods:
            return f"ORIGIN{common_methods[method_name]}"

        return None

    def _is_noise_value(self, value):
        """Check if value is noise"""
        v = value.lower()

        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return True

        if len(value) < 2:
            return True

        return False

    def _register_variable(self, var_name, var_value, filename, file_vars, confidence):
        """Register a variable with confidence scoring"""
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, var_value, re.IGNORECASE):
                return

        file_vars[var_name] = var_value

        if var_name not in self.variables or self.variables[var_name]['confidence'] < confidence:
            self.variables[var_name] = {
                'value': var_value,
                'source_file': filename,
                'confidence': confidence
            }

        if self._could_be_base_url(var_value):
            self.potential_bases[var_name] = var_value

        if self._is_base_url(var_value):
            self.global_scope[var_name] = var_value

    def _is_url_like(self, value):
        """Check if value looks like a URL or endpoint"""
        if len(value) < 2:
            return False
        return (
            value.startswith('http') or
            value.startswith('/') or
            value.startswith('#/') or
            value.startswith('ORIGIN') or
            any(term in value.lower() for term in ['api', 'endpoint', 'service', 'rest', 'graphql',
                                                    'fetch', 'data', 'dashboard', 'master', 'project'])
        )

    def _could_be_base_url(self, value):
        """Check if this could potentially be a base URL"""
        if len(value) < 3:
            return False

        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False

        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False

        return True

    def _is_base_url(self, value):
        """Check if this looks like a base URL"""
        for pattern in BASE_URL_BLACKLIST:
            if re.search(pattern, value, re.IGNORECASE):
                return False

        if len(value) < 5:
            return False

        if not (value.startswith('http') or value.startswith('/') or value.startswith('#/') or value.startswith('ORIGIN')):
            return False

        patterns = [
            r'^https?://[^/]+',
            r'^/',
            r'^#/',
            r'^ORIGIN',
        ]

        return any(re.search(p, value) for p in patterns)

    def resolve_with_fallback(self, var_name):
        """Resolve variable with multiple fallback strategies"""
        if var_name in self.global_scope:
            return self.global_scope[var_name]
        if var_name in self.potential_bases:
            return self.potential_bases[var_name]
        if var_name in self.variables:
            return self.variables[var_name]['value']
        if var_name in self.property_accesses:
            return self.property_accesses[var_name]
        if var_name in self.service_properties:
            return self.service_properties[var_name]['endpoint']

        if f"this.{var_name}" in self.variables:
            return self.variables[f"this.{var_name}"]['value']

        for prop in ['url', 'serverURL', 'baseURL', 'apiURL', 'rootUrl', 'baseUrl']:
            if var_name == prop and prop in self.property_accesses:
                return self.property_accesses[prop]

        return None

    def resolve_method_call(self, method_call_str):
        """Resolve a method call like 'this.getRootUrl()' to its return value"""
        method_call_str = method_call_str.strip()

        if method_call_str.endswith('()'):
            method_call_str = method_call_str[:-2]

        if method_call_str in self.methods:
            return self.methods[method_call_str]

        if method_call_str.startswith('this.'):
            method_name = method_call_str[5:]
            if method_name in self.methods:
                return self.methods[method_name]
        else:
            if f"this.{method_call_str}" in self.methods:
                return self.methods[f"this.{method_call_str}"]

        # FIX RC3-1: handle "this.obj.method" cross-object DI chain form
        # e.g. "this.o.getBase" → strip middle object → try "getBase"
        parts = method_call_str.split('.')
        if len(parts) >= 3 and parts[0] == 'this':
            plain_method = parts[-1]
            if plain_method in self.methods:
                result = self.methods[plain_method]
                # Depth-2: if result is a property reference (not a URL), resolve it
                if result and not result.startswith('http') and not result.startswith('/'):
                    resolved2 = self.resolve_with_fallback(result)
                    if resolved2:
                        return resolved2
                return result
            if f"this.{plain_method}" in self.methods:
                return self.methods[f"this.{plain_method}"]

        # FIX RC3-1b: handle "this.obj.prop" property chain
        # e.g. "this.appConfig.apiUrl"
        if len(parts) == 3 and parts[0] == 'this':
            obj_name, prop_name = parts[1], parts[2]
            cross_key = f"{obj_name}.{prop_name}"
            if cross_key in self.variables:
                return self.variables[cross_key]['value']
            if cross_key in self.property_accesses:
                return self.property_accesses[cross_key]

        # FIX FN-1: Deep Angular 3-level DI chain resolution.
        # Pattern: this.api.get('endpoint') where this.api is an injected service
        # whose getBase()/getApiBase() method returns the base URL.
        # Traverse: injected_service_var → method name → registered method return value.
        if len(parts) >= 3 and parts[0] == 'this':
            injected_obj = parts[1]   # e.g. 'api', 'o', 'config'
            method_name  = parts[-1]  # e.g. 'getBase', 'getApiBase', 'getUrl'
            # Try to find the service's method in the global method registry
            for candidate_key in (method_name, f"this.{method_name}",
                                   f"{injected_obj}.{method_name}"):
                if candidate_key in self.methods:
                    result = self.methods[candidate_key]
                    if result and (result.startswith('http') or result.startswith('/')):
                        return result
                    # Third-level resolve: result may be a property reference
                    if result:
                        resolved3 = (self.resolve_with_fallback(result)
                                     or self.property_accesses.get(result))
                        if resolved3 and (resolved3.startswith('http') or resolved3.startswith('/')):
                            return resolved3
            # Also try resolving the injected variable itself as a base URL
            base_via_var = (
                self.resolve_with_fallback(injected_obj)
                or self.resolve_with_fallback(f"this.{injected_obj}")
            )
            if base_via_var and (base_via_var.startswith('http') or base_via_var.startswith('/')):
                return base_via_var

        return None

    def get_all_base_urls(self):
        """Get all potential base URLs found"""
        return {**self.global_scope, **self.potential_bases, **self.property_accesses}

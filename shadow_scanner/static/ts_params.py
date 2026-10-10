"""TypeScript-aware API parameter mining (interfaces, HttpParams, FormGroup...)."""
import os
import re
# ==============================================================================
# TYPESCRIPT PARAMETER EXTRACTOR
# Deep multi-technique parameter mining — zero LLMs, zero Node.js.
#
# Techniques:
#   1. TypeScript interface/type-alias registry  (most accurate)
#   2. Generic type annotation .post<BodyType>() → interface fields
#   3. Angular HttpParams chain .set('key') .append('key')
#   4. Backward variable taint:  let body = {key: val} before HTTP call
#   5. URLSearchParams({key: val}) literal
#   6. Angular FormGroup({key: FormControl()}) field names
#   7. Refined forward object scan (fallback)
# ==============================================================================
class TypeScriptParameterExtractor:
    # Maximum number of parameters returned per endpoint — used consistently
    # by both the full extractor and the fallback proximity scan.
    _MAX_PARAMS = 10

    _NOISE = {
        'headers', 'body', 'method', 'credentials', 'mode', 'cache',
        'redirect', 'referrer', 'integrity', 'keepalive', 'signal',
        'Authorization', 'authorization', 'ContentType', 'contentType',
        'Accept', 'accept', 'Cookie', 'cookie', 'XCSRFToken', 'XAuthToken',
        'url', 'baseURL', 'baseUrl', 'timeout', 'withCredentials', 'data',
        'responseType', 'transformRequest', 'transformResponse',
        'validateStatus', 'maxRedirects', 'observe', 'reportProgress', 'context',
        'factory', 'providedIn', 'token', 'deps', 'useClass', 'useValue',
        'checksum', 'interceptors', 'onUploadProgress', 'onDownloadProgress',
        'loading', 'error', 'success', 'result', 'response', 'request',
        'type', 'name', 'value', 'index', 'key',
        'var', 'let', 'const', 'if', 'else', 'true', 'false', 'null', 'this',
        'return', 'class', 'function', 'new', 'delete', 'import', 'export',
        'from', 'async', 'await', 'catch', 'throw', 'try', 'finally',
        'style', 'className', 'children', 'ref', 'onClick', 'onChange',
        'label', 'title', 'message', 'description', 'placeholder',
        'disabled', 'visible', 'hidden', 'checked', 'selected',
    }

    def __init__(self):
        self._interfaces = {}
        self._type_aliases = {}

    def register_source_file(self, code, filepath=''):
        if not code:
            return 0
        ext = os.path.splitext(filepath)[1].lower() if filepath else '.ts'
        if ext not in ('.ts', '.tsx', '.js', '.jsx'):
            return 0
        before = len(self._interfaces) + len(self._type_aliases)
        self._parse_interfaces(code)
        self._parse_type_aliases(code)
        return (len(self._interfaces) + len(self._type_aliases)) - before

    def extract(self, code, call_pos):
        candidates = set()
        candidates.update(self._from_type_annotation(code, call_pos))
        candidates.update(self._from_http_params_chain(code, call_pos))
        candidates.update(self._from_backward_taint(code, call_pos))
        candidates.update(self._from_url_search_params(code, call_pos))
        candidates.update(self._from_form_group(code, call_pos))
        if not candidates:
            candidates.update(self._from_forward_scan(code, call_pos))
        return self._clean(sorted(candidates))[:self._MAX_PARAMS]

    def resolve_interface(self, type_name):
        return (self._interfaces.get(type_name)
                or self._type_aliases.get(type_name) or [])

    # ── Internal parsing ──────────────────────────────────────────────────────

    def _parse_interfaces(self, code):
        for m in re.finditer(
            r'(?:export\s+)?interface\s+(\w+)(?:\s+extends\s+[^{]+)?\s*\{', code
        ):
            body = self._brace_content(code, m.end() - 1)
            fields = self._fields_from_body(body)
            if fields:
                self._interfaces[m.group(1)] = fields

    def _parse_type_aliases(self, code):
        for m in re.finditer(r'(?:export\s+)?type\s+(\w+)\s*=\s*\{', code):
            body = self._brace_content(code, m.end() - 1)
            fields = self._fields_from_body(body)
            if fields:
                self._type_aliases[m.group(1)] = fields

    def _brace_content(self, code, start):
        if start >= len(code) or code[start] != '{':
            return ''
        depth = end = 0
        for i in range(start, min(start + 3000, len(code))):
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        return code[start + 1:end]

    def _fields_from_body(self, body):
        fields = []
        for m in re.finditer(
            r'^\s*["\']?(\w{2,40})["\']?\??\s*:\s*(?!\s*\()(?:[^\n;{},]{0,80})',
            body, re.MULTILINE
        ):
            f = m.group(1)
            if f not in ('constructor', 'ngOnInit', 'ngOnDestroy', 'toString', 'valueOf'):
                fields.append(f)
        return fields

    # ── Extraction techniques ─────────────────────────────────────────────────

    def _from_type_annotation(self, code, pos):
        window = code[max(0, pos - 150): pos + 150]
        params = []
        # Strong hint — type name ends in known DTO suffix
        for m in re.finditer(
            r'<(\w+(?:Request|Response|Body|Dto|Params|Data|Input|Payload|Form|Model))>',
            window
        ):
            params.extend(self.resolve_interface(m.group(1)))
        # Weaker: any PascalCase type close to the call
        for m in re.finditer(r'<([A-Z]\w{3,40})>', window):
            fields = self.resolve_interface(m.group(1))
            if fields:
                params.extend(fields)
        return params

    def _from_http_params_chain(self, code, pos):
        window = code[max(0, pos - 1500): pos + 500]
        params = []
        for m in re.finditer(r'\.(?:set|append)\s*\(\s*["\'](\w{2,40})["\']', window):
            params.append(m.group(1))
        for m in re.finditer(r'fromObject\s*\(\s*\{([^}]{0,500})\}', window):
            params.extend(re.findall(r'["\']?(\w{2,40})["\']?\s*:', m.group(1)))
        return params

    def _from_backward_taint(self, code, pos):
        before = code[max(0, pos - 2500): pos]
        params = []
        for m in re.finditer(
            r'(?:var|let|const)\s+(\w+)\s*=\s*\{([^}]{0,600})\}', before
        ):
            var_name = m.group(1).lower()
            if any(h in var_name for h in ('body', 'payload', 'data', 'request',
                                            'req', 'param', 'dto', 'form',
                                            'input', 'model', 'query', 'filter')):
                params.extend(re.findall(r'["\']?(\w{2,40})["\']?\s*:', m.group(2)))
        after = code[pos: pos + 700]
        for m in re.finditer(r'\{([^{}]{0,400})\}', after):
            keys = re.findall(r'["\']?(\w{2,40})["\']?\s*:', m.group(1))
            if keys:
                params.extend(keys)
                break
        return params

    def _from_url_search_params(self, code, pos):
        window = code[max(0, pos - 1000): pos + 500]
        params = []
        for m in re.finditer(r'URLSearchParams\s*\(\s*\{([^}]{0,400})\}', window):
            params.extend(re.findall(r'["\']?(\w{2,40})["\']?\s*:', m.group(1)))
        for m in re.finditer(
            r'(?:searchParams|params)\s*\.\s*(?:append|set)\s*\(\s*["\'](\w{2,40})["\']',
            window
        ):
            params.append(m.group(1))
        return params

    def _from_form_group(self, code, pos):
        window = code[max(0, pos - 2000): pos + 200]
        params = []
        for m in re.finditer(r'new\s+FormGroup\s*\(\s*\{([^}]{0,800})\}', window):
            params.extend(re.findall(r'["\']?(\w{2,40})["\']?\s*:', m.group(1)))
        for m in re.finditer(r'\.get\s*\(\s*["\'](\w{2,40})["\']', window):
            params.append(m.group(1))
        return params

    def _from_forward_scan(self, code, pos):
        ctx = code[pos: pos + 300]
        params = []
        for m in re.finditer(r'\{([^{}]{0,250})\}', ctx):
            keys = re.findall(r'["\']?([a-zA-Z][a-zA-Z0-9_]{1,39})["\']?\s*:', m.group(1))
            params.extend(keys)
            if len(params) >= 8:
                break
        return params

    def _clean(self, params):
        seen = set()
        result = []
        for p in params:
            if (p not in self._NOISE and p.lower() not in self._NOISE
                    and 2 <= len(p) <= 50 and p[0].isalpha() and p not in seen):
                seen.add(p)
                result.append(p)
        return result

"""JSON config file analysis."""
import json
import re

import requests

from shadow_scanner.config import API_INDICATORS, IGNORED_DOMAINS, NOISE_KEYWORDS, NOISE_PATTERNS
class JsonConfigMixin:
    """Endpoint extraction from JSON config files (environment.json etc.)."""

    def analyze_json_config(self, json_url):
        """Extract ALL string values from JSON config files"""
        try:
            r = self.session.get(json_url, timeout=10, verify=False)
            if r.status_code != 200:
                return

            data = r.json()
            filename = json_url.split('/')[-1]

            self._extract_from_json(data, filename, json_url)

        except json.JSONDecodeError:
            pass  # Not valid JSON
        except requests.exceptions.Timeout:
            pass  # Timeout
        except Exception:
            pass  # Other errors

    def _extract_from_json(self, data, filename, source_url, path=''):
        """Recursively extract ALL string values from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                if isinstance(value, str):
                    if len(value) > 3 and not value.isspace():
                        method = self._guess_method_from_key(key)
                        classification = self._classify_json_value(value, key)

                        if classification != "NOISE":
                            full_url = self.normalizer.normalize(value)

                            self.add_endpoint(
                                full_url,
                                method,
                                [],
                                "JSON_CONFIG",
                                filename,
                                classification,
                                75
                            )

                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, filename, source_url, current_path)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, filename, source_url, f"{path}[{i}]")

    def _classify_json_value(self, value, key):
        """Determine if a JSON string value is an endpoint"""
        v = value.lower()
        k = key.lower()

        for keyword in NOISE_KEYWORDS:
            if keyword in v:
                return "NOISE"

        if any(re.search(p, value) for p in NOISE_PATTERNS):
            return "NOISE"

        if any(re.search(p, value, re.IGNORECASE) for p in API_INDICATORS):
            return "BACKEND_API"

        api_key_indicators = ['api', 'endpoint', 'url', 'service', 'path', 'route', 'dashboard']
        if any(ind in k for ind in api_key_indicators):
            if value.startswith('/') or value.startswith('http') or value.startswith('#/'):
                return "BACKEND_API"

        if value.startswith('http'):
            if not any(d in v for d in IGNORED_DOMAINS):
                return "EXTERNAL_API"

        if (value.startswith('/') or value.startswith('#/')) and len(value) > 3:
            if '/' in value[1:] or '#' in value:
                return "FRONTEND_ROUTE"

        return "NOISE"

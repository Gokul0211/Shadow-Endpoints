"""Front-end navigation / route extraction."""
import re

from shadow_scanner.config import HASH_ROUTE_PATTERNS, NOISE_KEYWORDS
class RoutePatternsMixin:
    """Front-end navigation targets (router, history, hash routes, location.origin)."""

    def _extract_router_navigation(self, code, source):
        """router.navigate / route.navigate targets and window.open sinks."""
        for m in re.finditer(r'this\.router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV_THIS", "FRONTEND_ROUTE", 85)

        for m in re.finditer(r'this\.route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV_THIS", "FRONTEND_ROUTE", 85)

        for m in re.finditer(r'router\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTER_NAV", "FRONTEND_ROUTE", 80)

        for m in re.finditer(r'route\.navigate(?:ByUrl)?\s*\(\s*[\'"`]([^\'"`]+)', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "ROUTE_NAV", "FRONTEND_ROUTE", 80)

        for m in re.finditer(r'window\.open\s*\(\s*[\'"]([^\'"]+)[\'"]', code, re.IGNORECASE):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN", "OPEN_REDIRECT_SINK", 90)

    def _extract_history_navigation(self, code, source):
        """history.push(...) and React Router navigate(...)."""
        for m in re.finditer(
            r"""(?:history|props\.history|this\.props\.history)\.push\s*\(\s*['"`]([^'"`]+)""",
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "HISTORY_PUSH", "FRONTEND_ROUTE", 80)

        for m in re.finditer(
            r"""\bnavigate\s*\(\s*['"`]([^'"`]{3,60})['"`]""",
            code, re.IGNORECASE
        ):
            full_url = self.normalizer.normalize(m.group(1))
            self.process(full_url, "GET", m.start(), code, source, "REACT_NAVIGATE", "FRONTEND_ROUTE", 75)

    def _extract_location_and_hash_routes(self, code, source):
        """location.origin + "/path", hash routes, window.open(location.origin + ...)."""
        # Location patterns
        for m in re.finditer(r'location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "LOCATION_ORIGIN", "FRONTEND_ROUTE", 85)

        # Hash routes
        for pattern in HASH_ROUTE_PATTERNS:
            for m in re.finditer(pattern, code):
                route = m.group(1)
                if self._is_valid_route(route):
                    full_url = self.normalizer.normalize(route)
                    self.process(full_url, "GET", m.start(), code, source, "HASH_ROUTE", "FRONTEND_ROUTE", 75)

        for m in re.finditer(r'window\.open\s*\(\s*location\.origin\s*\+\s*["\']([^"\']+)["\']', code, re.IGNORECASE):
            path = m.group(1)
            clean_path = self._extract_clean_route(path)
            if clean_path:
                full_url = self.normalizer.normalize(clean_path)
                self.process(full_url, "GET", m.start(), code, source, "WINDOW_OPEN_ROUTE", "FRONTEND_ROUTE", 88)

    def _extract_clean_route(self, path):
        """Extract clean route from JavaScript concatenation"""
        path = path.strip()

        if '+' in path:
            path = path.split('+')[0]

        if '(' in path and ')' in path:
            parts = re.split(r'[()]', path)
            for part in parts:
                if '#/' in part:
                    path = part
                    break

        path = path.strip('"\'')

        if self._is_valid_route(path):
            return path
        return None

    def _is_valid_route(self, route):
        """Check if route is valid"""
        if not route:
            return False

        route_lower = route.lower()

        for keyword in NOISE_KEYWORDS:
            if keyword in route_lower:
                return False

        return ('#/' in route or route.startswith('/') or route.startswith('#/'))

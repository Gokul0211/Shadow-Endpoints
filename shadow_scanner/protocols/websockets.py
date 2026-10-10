"""WebSocket endpoint discovery (static JS regexes + Playwright capture)."""
import re

from shadow_scanner.config import logger
class WebSocketDiscovery:
    """
    Discovers WebSocket endpoints and captures messages.
    Intercepts ws:// and wss:// connections during dynamic phase.
    """

    def __init__(self):
        self.websocket_endpoints = []
        self.captured_messages = {}

    def discover_from_js(self, js_code, source):
        """Extract WebSocket endpoints from JavaScript code"""
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.connect\s*\(\s*[\'"`](wss?://[^\'"`]+)[\'"`]',
            r'[\'"`](wss?://[^\'"`]+)[\'"`]',
            r'socketUrl\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'wsUrl\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
        ]

        found = []
        for pattern in ws_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                ws_url = match.group(1)
                if self._is_valid_websocket(ws_url):
                    found.append({
                        'endpoint': ws_url,
                        'source': source,
                        'protocol': 'wss' if ws_url.startswith('wss') else 'ws'
                    })

        return found

    def _is_valid_websocket(self, url):
        """Check if URL is a valid WebSocket endpoint"""
        if not url:
            return False

        url_lower = url.lower()

        # Must start with ws:// or wss:// or be a path
        if not (url_lower.startswith('ws://') or url_lower.startswith('wss://') or url_lower.startswith('/')):
            return False

        # Skip noise (do NOT filter localhost/127.0.0.1 — they are valid local targets)
        noise_patterns = ['example.com', 'test.example', 'placeholder']
        if any(noise in url_lower for noise in noise_patterns):
            return False

        return True

    # Injected with page.add_init_script() so it runs before the page's own
    # scripts on EVERY navigation. (It used to be injected with page.evaluate()
    # before page.goto(); navigation then replaced the window and the hook was
    # lost, so Playwright-side WebSocket capture never recorded anything.)
    _WS_HOOK_SCRIPT = """
        (function() {
            if (window.__wsPatched || typeof window.WebSocket !== 'function') return;
            window.__wsPatched = true;
            window.__ws_endpoints = window.__ws_endpoints || [];
            window.__ws_messages  = window.__ws_messages  || [];

            const OriginalWebSocket = window.WebSocket;
            const _sample = (d) => { try { return String(d).substring(0, 500); } catch (_) { return ''; } };

            const PatchedWebSocket = function(url, protocols) {
                const wsUrl = String(url);
                try { window.__ws_endpoints.push({url: wsUrl, timestamp: Date.now()}); } catch (_) {}

                const ws = protocols === undefined
                    ? new OriginalWebSocket(url)
                    : new OriginalWebSocket(url, protocols);

                const originalSend = ws.send;
                ws.send = function(data) {
                    try {
                        window.__ws_messages.push({type: 'outgoing', url: wsUrl,
                                                   data: _sample(data), timestamp: Date.now()});
                    } catch (_) {}
                    return originalSend.apply(this, arguments);
                };
                ws.addEventListener('message', function(event) {
                    try {
                        window.__ws_messages.push({type: 'incoming', url: wsUrl,
                                                   data: _sample(event.data), timestamp: Date.now()});
                    } catch (_) {}
                });
                return ws;
            };
            // Keep `instanceof WebSocket` and WebSocket.OPEN etc. working for the page.
            PatchedWebSocket.prototype = OriginalWebSocket.prototype;
            ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function(k) {
                try { PatchedWebSocket[k] = OriginalWebSocket[k]; } catch (_) {}
            });
            window.WebSocket = PatchedWebSocket;
        })();
    """

    def intercept_playwright_websockets(self, page):
        """
        Set up WebSocket interception in a Playwright page.
        Must be called BEFORE page.goto(); captures connections and messages
        into window.__ws_endpoints / window.__ws_messages on every document.
        """
        try:
            page.add_init_script(self._WS_HOOK_SCRIPT)
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

    def extract_captured_websockets(self, page):
        """Extract captured WebSocket data from page"""
        try:
            endpoints = page.evaluate("() => window.__ws_endpoints || []")
            messages = page.evaluate("() => window.__ws_messages || []")

            for endpoint in endpoints:
                if endpoint['url'] not in self.websocket_endpoints:
                    self.websocket_endpoints.append(endpoint['url'])

            for msg in messages:
                url = msg['url']
                if url not in self.captured_messages:
                    self.captured_messages[url] = []
                self.captured_messages[url].append(msg)
        except Exception as _exc:
            logger.debug(f"[Suppressed] {_exc}")

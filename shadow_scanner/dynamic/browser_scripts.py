"""
JavaScript injected into every page during Phase 3 (Playwright).

INTERCEPTOR_SCRIPT patches fetch / XMLHttpRequest / EventSource /
navigator.sendBeacon / axios / GraphQL-over-fetch at the prototype level and
records every call in window.__api_calls (read back by DynamicInterceptor).
"""

INTERCEPTOR_SCRIPT = """
            (function() {
            'use strict';

            window.__api_calls    = window.__api_calls    || [];
            window.__lazy_chunks  = window.__lazy_chunks  || [];
            window.__sse_urls     = window.__sse_urls     || [];
            window.__beacon_urls  = window.__beacon_urls  || [];

            const _push = (obj) => {
                // Dedup on url+method
                const key = obj.method + ':' + obj.url;
                if (!window.__api_calls._seen) window.__api_calls._seen = new Set();
                if (window.__api_calls._seen.has(key)) return;
                window.__api_calls._seen.add(key);
                window.__api_calls.push(obj);
            };

            // ── 1. fetch() ──────────────────────────────────────────────────
            if (!window.__fetchPatched) {
                const _origFetch = window.fetch;
                window.fetch = function() {
                    const inp = arguments[0];
                    let url = '', method = (arguments[1] && arguments[1].method) || 'GET';
                    if (typeof inp === 'string') { url = inp; }
                    else if (inp && inp.url)     { url = inp.url; method = inp.method || method; }
                    if (url) _push({type:'fetch', url:url, method:method.toUpperCase()});
                    return _origFetch.apply(this, arguments);
                };
                window.__fetchPatched = true;
            }

            // ── 2. XMLHttpRequest.prototype ─────────────────────────────────
            if (!XMLHttpRequest.prototype.__xhrPatched) {
                const _origOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url) {
                    if (url) _push({type:'xhr', url:url, method:(method||'GET').toUpperCase()});
                    return _origOpen.apply(this, arguments);
                };
                XMLHttpRequest.prototype.__xhrPatched = true;
            }

            // ── 3. EventSource (SSE) ────────────────────────────────────────
            if (typeof EventSource !== 'undefined' && !window.__esPatched) {
                const _origES = EventSource;
                window.EventSource = function(url, opts) {
                    if (url) {
                        _push({type:'eventsource', url:String(url), method:'GET'});
                        window.__sse_urls.push(String(url));
                    }
                    return new _origES(url, opts);
                };
                window.EventSource.prototype = _origES.prototype;
                window.__esPatched = true;
            }

            // ── 4. navigator.sendBeacon ─────────────────────────────────────
            if (navigator.sendBeacon && !window.__beaconPatched) {
                const _origBeacon = navigator.sendBeacon.bind(navigator);
                navigator.sendBeacon = function(url, data) {
                    if (url) {
                        _push({type:'beacon', url:String(url), method:'POST'});
                        window.__beacon_urls.push(String(url));
                    }
                    return _origBeacon(url, data);
                };
                window.__beaconPatched = true;
            }

            // ── 5. Axios instance detection ─────────────────────────────────
            // When axios is loaded, patch its defaults.baseURL watcher so any
            // baseURL set after page load is captured.
            const _patchAxios = (ax) => {
                if (!ax || ax.__asPatched) return;
                ax.__asPatched = true;
                const _origReq = ax.request && ax.request.bind(ax);
                if (_origReq) {
                    ax.request = function(cfg) {
                        const url = (cfg && cfg.url) || '';
                        const base = (cfg && cfg.baseURL) || (ax.defaults && ax.defaults.baseURL) || '';
                        const full = url.startsWith('http') ? url : base.replace(/\\/$/, '') + '/' + url.replace(/^\\//, '');
                        if (full && full.includes('/')) _push({type:'axios', url:full, method:(cfg && cfg.method || 'GET').toUpperCase()});
                        return _origReq(cfg);
                    };
                }
            };
            // Try to patch known global axios instances on load
            setTimeout(() => {
                try { if (window.axios)   _patchAxios(window.axios);   } catch(_) {}
                try { if (window.api)     _patchAxios(window.api);     } catch(_) {}
                try { if (window.http)    _patchAxios(window.http);    } catch(_) {}
                try { if (window.client)  _patchAxios(window.client);  } catch(_) {}
            }, 500);

            // ── 6. GraphQL over fetch — detect operation names ───────────────
            // When fetch() is called with a JSON body containing an operationName,
            // store it so we can associate the GQL operation with the endpoint.
            const _origFetch2 = window.fetch;
            if (!window.__gqlFetchPatched) {
                window.fetch = function() {
                    const opts = arguments[1];
                    if (opts && opts.body && typeof opts.body === 'string') {
                        try {
                            const parsed = JSON.parse(opts.body);
                            if (parsed.operationName || parsed.query) {
                                const gqlUrl = typeof arguments[0] === 'string' ? arguments[0] : (arguments[0] && arguments[0].url) || '';
                                const opName = parsed.operationName || '';
                                if (gqlUrl && opName) {
                                    _push({type:'graphql', url: gqlUrl + '#' + opName, method:'GRAPHQL'});
                                }
                            }
                        } catch(_) {}
                    }
                    return _origFetch2.apply(this, arguments);
                };
                window.__gqlFetchPatched = true;
            }

            })();
            """

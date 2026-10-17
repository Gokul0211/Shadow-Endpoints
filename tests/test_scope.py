"""Scope and credential isolation (finding S37)."""
import os
import sys
import unittest
from unittest import mock

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shadow_scanner.core.http_client import HttpClient  # noqa: E402
from shadow_scanner.core.scope import OutOfScope, Scope  # noqa: E402

TARGET = 'https://app.example.com'


class _Resp:
    status_code = 200
    content = b'ok'


class ScopeRules(unittest.TestCase):
    def test_first_party(self):
        sc = Scope(TARGET, ['api.partner.io'])
        self.assertTrue(sc.first_party('https://app.example.com:8443/x'))
        self.assertTrue(sc.first_party('https://api.example.com/x'))
        self.assertTrue(sc.first_party('https://eu.api.partner.io/x'))
        self.assertFalse(sc.first_party('https://cdn.jsdelivr.net/x.js'))
        self.assertFalse(sc.first_party('https://example.com.evil.net/x'))

    def test_login_host_is_added(self):
        sc = Scope(TARGET)
        sc.add('https://sso.other.org/login')
        self.assertTrue(sc.credentials_ok('https://sso.other.org/token'))

    def test_strict_only_blocks_http_schemes(self):
        sc = Scope(TARGET, strict=True)
        self.assertFalse(sc.allows('https://cdn.jsdelivr.net/x.js'))
        self.assertFalse(sc.allows('wss://other.net/socket'))
        self.assertTrue(sc.allows('data:text/plain,hi'))
        self.assertTrue(sc.allows('https://app.example.com/a'))
        self.assertTrue(Scope(TARGET).allows('https://cdn.jsdelivr.net/x.js'))

    def test_safe_headers(self):
        sc = Scope(TARGET)
        out = sc.safe_headers({'Authorization': 'Bearer t', 'Cookie': 'a=b', 'X-Api-Key': 'k', 'Accept': '*/*'})
        self.assertEqual(out, {'Accept': '*/*'})


class ClientIsolation(unittest.TestCase):
    def _client(self, **kw):
        s = requests.Session()
        s.headers.update({'Authorization': 'Bearer secret-token', 'Accept': 'application/json'})
        s.cookies.set('sid', 'cookie-secret')
        return HttpClient(s, scope=Scope(TARGET, **kw), retries=0)

    def test_third_party_gets_no_credentials(self):
        c = self._client()
        with mock.patch('shadow_scanner.core.http_client.requests.request', return_value=_Resp()) as m:
            c.get('https://cdn.jsdelivr.net/lib.js', headers={'X-Api-Key': 'k'})
        _, kw = m.call_args
        sent = {k.lower() for k in kw['headers']}
        self.assertNotIn('authorization', sent)
        self.assertNotIn('x-api-key', sent)
        self.assertIn('accept', sent)
        self.assertEqual(c.stats()['scope']['requests_sent_without_credentials'], 1)

    def test_first_party_uses_session(self):
        c = self._client()
        with mock.patch.object(requests.Session, 'get', return_value=_Resp()) as m, \
                mock.patch('shadow_scanner.core.http_client.requests.request') as other:
            c.get(TARGET + '/api/x')
        m.assert_called_once()
        other.assert_not_called()

    def test_strict_refuses_and_does_not_charge_budget(self):
        c = self._client(strict=True)
        with mock.patch('shadow_scanner.core.http_client.requests.request') as m:
            with self.assertRaises(OutOfScope):
                c.get('https://tracker.example.net/p')
        m.assert_not_called()
        st = c.stats()
        self.assertEqual(st['requests'], 0)
        self.assertEqual(st['scope']['requests_blocked'], 1)

    def test_browser_requests_share_the_budget(self):
        c = HttpClient(requests.Session(), max_requests=2)
        self.assertTrue(c.note_browser_request())
        self.assertTrue(c.note_browser_request())
        self.assertFalse(c.note_browser_request())
        self.assertEqual(c.stats()['by_phase']['browser']['requests'], 2)


if __name__ == '__main__':
    unittest.main()

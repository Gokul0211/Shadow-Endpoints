"""Run metadata for every report: what produced it, with which settings.

Secrets never appear: any option listed in SECRET_OPTIONS is written as
"<redacted>" (or omitted when it was not given), and so is any option whose
name looks like a credential.
"""
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time

SECRET_OPTIONS = frozenset({'password', 'bearer', 'cookies', 'mfa_secret'})
_SECRET_NAME = re.compile(r'pass|secret|token|bearer|cookie|key|auth', re.I)
REDACTED = '<redacted>'

# Secrets may also be supplied through the environment, so they need not be
# typed on the command line (where shell history keeps them).
ENV_FOR_OPTION = {
    'password': 'SHADOW_PASSWORD',
    'bearer': 'SHADOW_BEARER',
    'cookies': 'SHADOW_COOKIES',
    'mfa_secret': 'SHADOW_MFA_SECRET',
}


def apply_env_secrets(args):
    """Fill unset secret options from SHADOW_* environment variables."""
    for opt, env in ENV_FOR_OPTION.items():
        if getattr(args, opt, None) in (None, '') and os.environ.get(env):
            setattr(args, opt, os.environ[env])
    return args


def is_secret_option(name):
    return name in SECRET_OPTIONS or bool(_SECRET_NAME.search(name or ''))


def redact_args(args):
    """{option: value} with every secret replaced by '<redacted>' (None stays None)."""
    out = {}
    for name, value in sorted(vars(args).items()):
        if name.startswith('_'):
            continue
        if is_secret_option(name) and value not in (None, False, ''):
            out[name] = REDACTED
        else:
            out[name] = value
    return out


def _git(repo, *cmd):
    try:
        r = subprocess.run(['git', '-C', repo, *cmd], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def scanner_version_info():
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sha = _git(repo, 'rev-parse', 'HEAD')
    dirty = None
    if sha:
        status = _git(repo, 'status', '--porcelain')
        dirty = bool(status)
    return {'git_sha': sha, 'git_dirty': dirty}


def _pkg_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:
        return None


def environment_info():
    return {
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'packages': {p: _pkg_version(p) for p in
                     ('requests', 'beautifulsoup4', 'esprima', 'playwright', 'pandas', 'openpyxl')},
    }


def config_hash(config_module):
    """Hash of the settings that change results (blocklists, thresholds, probing)."""
    from shadow_scanner.core.scoring import BayesianConfidenceScorer as B
    payload = {
        'blocked_keywords': sorted(config_module._BLOCKED_KEYWORDS),
        'blocked_patterns': sorted(config_module._BLOCKED_PATTERNS),
        'ignored_domains': sorted(config_module.IGNORED_DOMAINS),
        'probing': config_module.PROBING_ENABLED,
        'prior': B.PRIOR,
        'tiers': [B.TIER_VERIFIED, B.TIER_BACKEND, B.TIER_LOW_CONF],
        'lr': sorted(B.LR.items()),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]


class RunRecorder:
    """Collects per-phase wall time and request counts during a scan."""

    def __init__(self):
        self.started = time.time()
        self.phases = {}          # phase -> {'seconds': float, 'requests': int}
        self._phase = None
        self._t0 = None
        self._req0 = 0
        self.http = None          # core.http_client.HttpClient, when present

    def _requests(self):
        return self.http.stats()['requests'] if self.http else 0

    def start_phase(self, name):
        self.end_phase()
        self._phase, self._t0, self._req0 = name, time.time(), self._requests()

    def end_phase(self):
        if self._phase is None:
            return
        d = self.phases.setdefault(self._phase, {'seconds': 0.0, 'requests': 0})
        d['seconds'] = round(d['seconds'] + time.time() - self._t0, 3)
        d['requests'] += self._requests() - self._req0
        self._phase = None

    def build(self, args, config_module):
        self.end_phase()
        meta = {
            'started': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.started)),
            'wall_seconds': round(time.time() - self.started, 3),
            'scanner': scanner_version_info(),
            'environment': environment_info(),
            'config_hash': config_hash(config_module),
            'args': redact_args(args),
            'phases': self.phases,
        }
        if self.http:
            meta['http'] = self.http.stats()
        return meta

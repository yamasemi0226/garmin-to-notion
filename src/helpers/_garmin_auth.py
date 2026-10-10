"""Authentication only: no raw exceptions, response bodies or credentials in logs."""
import base64
import json
import logging
import os
import re
from urllib.parse import quote

import requests
from cryptography.fernet import Fernet
from garminconnect import Garmin


class AuthError(RuntimeError):
    pass


def status_of(exc):
    """Inspect chains without rendering them; return only an HTTP status."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        response = getattr(exc, 'response', None)
        status = getattr(response, 'status_code', None)
        if isinstance(status, int):
            return status
        match = re.search(r'(?:API Error |DI token refresh failed: )(\d{3})', str(exc))
        if match:
            return int(match[1])
        exc = exc.__cause__ or exc.__context__
    return None


class TokenStore:
    """Fernet-encrypted state on a dedicated branch, read at execution time.

    GitHub's SHA precondition prevents overwriting a concurrent writer. Never
    fall back to bootstrap if an existing state cannot be read or decrypted.
    """
    def __init__(self):
        repository = os.getenv('GITHUB_REPOSITORY', '')
        pat = os.getenv('GARMIN_STATE_GITHUB_TOKEN', '')
        key = os.getenv('GARMIN_STATE_KEY', '')
        if not all((repository, pat, key)):
            raise AuthError('AUTH_STORAGE_CONFIG: set GARMIN_STATE_KEY and GARMIN_STATE_GITHUB_TOKEN.')
        try:
            self.cipher = Fernet(key.encode())
        except Exception:
            raise AuthError('AUTH_STORAGE_CONFIG: invalid encryption key.') from None
        self.url = f'https://api.github.com/repos/{repository}/contents/garmin-session.enc'
        self.branch = 'garmin-auth-state'
        self.headers = {'Authorization': f'Bearer {pat}', 'Accept': 'application/vnd.github+json',
                        'X-GitHub-Api-Version': '2022-11-28'}
        self.sha = None
        self.last = None

    def request(self, method, **kwargs):
        try:
            response = requests.request(method, self.url, headers=self.headers, timeout=30, **kwargs)
        except Exception:
            raise AuthError('AUTH_STORAGE_NETWORK: state request failed; retry later.') from None
        return response

    def load(self, bootstrap):
        response = self.request('GET', params={'ref': self.branch})
        if response.status_code == 404:
            # Distinguish an absent file from inaccessible repository/branch.
            try:
                branch = requests.get(self.url.replace('/contents/garmin-session.enc',
                    '/branches/' + quote(self.branch, safe='')), headers=self.headers, timeout=30)
            except Exception:
                raise AuthError('AUTH_STORAGE_NETWORK: branch check failed.') from None
            if branch.status_code != 200:
                raise AuthError('AUTH_STORAGE_CONFIG: create garmin-auth-state branch and check PAT permissions.')
            return bootstrap
        if response.status_code != 200:
            raise AuthError(f'AUTH_STORAGE_READ: HTTP {response.status_code}; check PAT permissions.')
        try:
            data = response.json()
            self.sha = data['sha']
            self.last = self.cipher.decrypt(base64.b64decode(data['content'])).decode()
            return self.last
        except Exception:
            raise AuthError('AUTH_STORAGE_DECRYPT: restore the original key; do not reuse stale bootstrap tokens.') from None

    def save(self, token):
        if token == self.last:
            return
        payload = {'message': 'Update encrypted Garmin session', 'branch': self.branch,
                   'content': base64.b64encode(self.cipher.encrypt(token.encode())).decode()}
        if self.sha:
            payload['sha'] = self.sha
        response = self.request('PUT', json=payload)
        if response.status_code not in (200, 201):
            raise AuthError(f'AUTH_STORAGE_WRITE: HTTP {response.status_code}; stop and check permissions/concurrent writers.')
        try:
            self.sha = response.json()['content']['sha']
        except Exception:
            raise AuthError('AUTH_STORAGE_WRITE: invalid acknowledgement; stop and inspect state.') from None
        self.last = token


def authenticate(token, save, factory=Garmin):
    # The pinned library logs tokens and response bodies at DEBUG. Disable its
    # two loggers even if a caller has enabled global debug logging.
    for name in ('garminconnect', 'garminconnect.client'):
        logging.getLogger(name).disabled = True
    try:
        data = json.loads(token or '')
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k]
                for k in ('di_token', 'di_refresh_token', 'di_client_id')):
            raise ValueError
    except Exception:
        raise AuthError('AUTH_REAUTH_REQUIRED: invalid/legacy DI token format; generate a new session locally.') from None
    garmin = factory()
    client = garmin.client
    refresh_outcome = None
    fatal_storage_error = None
    original_refresh = client._refresh_di_token

    def refresh():
        nonlocal refresh_outcome, fatal_storage_error
        if fatal_storage_error:
            raise AuthError(fatal_storage_error)
        try:
            original_refresh()
        except Exception as exc:
            status = status_of(exc)
            if status in (400, 401):
                refresh_outcome = 'AUTH_REFRESH_REJECTED: refresh credential rejected; local reauthentication may be required.'
            elif status == 403:
                refresh_outcome = 'AUTH_REFRESH_FORBIDDEN: Garmin rejected refresh access; check service/network before reauthenticating.'
            else:
                refresh_outcome = 'AUTH_REFRESH_TRANSIENT: refresh unavailable; retry later without reauthentication.'
            raise AuthError(refresh_outcome) from None
        refresh_outcome = 'success'
        try:
            save(client.dumps())  # Persist rotation before profile or Notion calls.
        except AuthError as exc:
            fatal_storage_error = str(exc)
            raise AuthError(fatal_storage_error) from None
        print('AUTH_REFRESH_OK: updated session persisted.')

    client._refresh_di_token = refresh
    # Bypass login's length heuristic and exception-swallowing token loader.
    try:
        client.loads(json.dumps(data))
        if client._token_expires_soon():
            refresh()
        save(client.dumps())  # Seed durable state before any API-side refresh.
    except AuthError:
        raise
    except Exception:
        raise AuthError('AUTH_REAUTH_REQUIRED: session could not be loaded.') from None

    # The upstream _refresh_session swallows errors, including persistence errors.
    # Replace it so failed rotation storage cannot allow synchronization to proceed.
    client._refresh_session = refresh
    original_loads = client.loads
    client.loads = lambda _: None
    try:
        garmin.login(tokenstore='x' * 513)
    except Exception as exc:
        if isinstance(exc, AuthError):
            raise AuthError(str(exc)) from None
        chained = exc
        seen = set()
        while chained is not None and id(chained) not in seen:
            seen.add(id(chained))
            if isinstance(chained, AuthError):
                raise AuthError(str(chained)) from None
            chained = chained.__cause__ or chained.__context__
        status = status_of(exc)
        if refresh_outcome and refresh_outcome != 'success':
            message = refresh_outcome
        elif status == 401 and refresh_outcome == 'success':
            message = 'AUTH_API_REJECTED: refreshed access token still rejected (401); check Garmin service/account before reauthentication.'
        elif status == 403:
            message = 'AUTH_API_FORBIDDEN: Garmin denied API access; check service/network.'
        else:
            message = 'AUTH_API_UNAVAILABLE: profile/settings request failed; retry later. No reauthentication inferred.'
        raise AuthError(message) from None
    finally:
        client.loads = original_loads
    save(client.dumps())
    print('AUTH_OK: session verified.')
    return garmin

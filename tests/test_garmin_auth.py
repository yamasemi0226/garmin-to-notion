import contextlib
import io
import json
import os
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from garminconnect import Garmin
from garminconnect.exceptions import GarminConnectConnectionError
from src.helpers._garmin_auth import AuthError, TokenStore, authenticate

TOKEN = json.dumps(dict(di_token='SECRET_ACCESS', di_refresh_token='SECRET_REFRESH', di_client_id='client'))


class AuthTests(unittest.TestCase):
    def client(self, expired=False):
        # Exercise the real 0.3.3 login and request logic with fake HTTP only.
        garmin = Garmin()
        garmin.client._token_expires_soon = Mock(return_value=expired)
        def rotated():
            garmin.client.di_token = 'SECRET_NEW_ACCESS'
            garmin.client.di_refresh_token = 'SECRET_NEW_REFRESH'
            garmin.client._token_expires_soon.return_value = False
        garmin.client._refresh_di_token = Mock(side_effect=rotated)
        def response(status, data):
            return Mock(status_code=status, json=Mock(return_value=data), text='SECRET_RESPONSE')
        self.ok_profile = response(200, {'displayName': 'test'})
        self.ok_settings = response(200, {'userData': {}})
        self.unauthorized = response(401, {'message': 'SECRET_RESPONSE'})
        garmin.client._api_session.request = Mock(side_effect=[self.ok_profile, self.ok_settings])
        return garmin

    def test_proactive_rotation_is_saved_before_profile(self):
        garmin = self.client(True)
        saved = []
        original_refresh = garmin.client._refresh_di_token
        authenticate(TOKEN, saved.append, lambda: garmin)
        self.assertIn('SECRET_NEW_REFRESH', saved[0])
        self.assertEqual(original_refresh.call_count, 1)

    def test_401_refresh_retry_recovers(self):
        garmin = self.client()
        garmin.client._api_session.request.side_effect = [self.unauthorized, self.ok_profile, self.ok_settings]
        saved = []
        authenticate(TOKEN, saved.append, lambda: garmin)
        self.assertIn('SECRET_NEW_REFRESH', saved[-1])

    @patch('garminconnect.time.sleep')
    def test_refreshed_token_still_rejected_is_not_proof_of_expiry(self, _):
        garmin = self.client()
        garmin.client._api_session.request.side_effect = None
        garmin.client._api_session.request.return_value = self.unauthorized
        with self.assertRaisesRegex(AuthError, 'AUTH_API_REJECTED') as caught:
            authenticate(TOKEN, lambda _: None, lambda: garmin)
        self.assertNotIn('SECRET', str(caught.exception))

    @patch('garminconnect.time.sleep')
    def test_refresh_rejection_and_transient(self, _):
        for status, code in [(401, 'AUTH_REFRESH_REJECTED'), (503, 'AUTH_REFRESH_TRANSIENT'), (403, 'AUTH_REFRESH_FORBIDDEN')]:
            with self.subTest(status=status):
                garmin = self.client(True)
                garmin.client._refresh_di_token.side_effect = GarminConnectConnectionError(f'DI token refresh failed: {status} SECRET_RESPONSE')
                with self.assertRaisesRegex(AuthError, code) as caught:
                    authenticate(TOKEN, lambda _: None, lambda: garmin)
                self.assertNotIn('SECRET', str(caught.exception))

    def test_invalid_token_is_safe(self):
        with self.assertRaisesRegex(AuthError, 'AUTH_REAUTH_REQUIRED') as caught:
            authenticate('SECRET_BAD_JSON', lambda _: None)
        self.assertNotIn('SECRET', str(caught.exception))

    @patch('garminconnect.time.sleep')
    def test_storage_failure_during_401_stops_login(self, _):
        garmin = self.client()
        garmin.client._api_session.request.side_effect = [self.unauthorized] * 3
        save = Mock(side_effect=[None, AuthError('AUTH_STORAGE_WRITE'), AuthError('AUTH_STORAGE_WRITE'), AuthError('AUTH_STORAGE_WRITE')])
        with self.assertRaisesRegex(AuthError, 'AUTH_STORAGE_WRITE'):
            authenticate(TOKEN, save, lambda: garmin)

    def test_refresh_during_later_sync_request_is_persisted(self):
        garmin = self.client()
        saved = []
        authenticate(TOKEN, saved.append, lambda: garmin)
        garmin.client._api_session.request.side_effect = [self.unauthorized, self.ok_profile]
        garmin.client.connectapi('/activitylist-service/activities/search/activities')
        self.assertIn('SECRET_NEW_REFRESH', saved[-1])

    def test_valid_session_does_not_reauthenticate_or_refresh(self):
        garmin = self.client()
        original_refresh = garmin.client._refresh_di_token
        garmin.client.login = Mock(side_effect=AssertionError('password login must never occur'))
        authenticate(TOKEN, lambda _: None, lambda: garmin)
        original_refresh.assert_not_called()
        garmin.client.login.assert_not_called()

    def test_stdout_does_not_include_credentials(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            authenticate(TOKEN, lambda _: None, lambda: self.client(True))
        self.assertNotIn('SECRET', output.getvalue())


class StoreTests(unittest.TestCase):
    def store(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo', 'GARMIN_STATE_KEY': Fernet.generate_key().decode(), 'GARMIN_STATE_GITHUB_TOKEN': 'SECRET_PAT'}):
            return TokenStore()

    def test_encrypted_roundtrip_fresh_read_and_sha(self):
        store = self.store()
        store.request = Mock(return_value=Mock(status_code=201, json=lambda: {'content': {'sha': 'newsha'}}))
        store.save(TOKEN)
        payload = store.request.call_args.kwargs['json']
        self.assertNotIn('SECRET', str(payload))
        store.request.return_value = Mock(status_code=200, json=lambda: {'sha': 'newsha', 'content': payload['content']})
        self.assertEqual(store.load('stale'), TOKEN)
        store.request.return_value = Mock(status_code=200, json=lambda: {'content': {'sha': 'nextsha'}})
        store.save(TOKEN.replace('SECRET_REFRESH', 'ROTATED'))
        self.assertEqual(store.request.call_args.kwargs['json']['sha'], 'newsha')

    def test_existing_corrupt_state_never_falls_back(self):
        store = self.store()
        store.request = Mock(return_value=Mock(status_code=200, json=lambda: {'sha': 'sha', 'content': 'bad'}))
        with self.assertRaisesRegex(AuthError, 'AUTH_STORAGE_DECRYPT'):
            store.load(TOKEN)

    @patch('src.helpers._garmin_auth.requests.get')
    def test_migration_only_when_branch_exists(self, get):
        store = self.store()
        store.request = Mock(return_value=Mock(status_code=404))
        get.return_value.status_code = 200
        self.assertEqual(store.load(TOKEN), TOKEN)
        get.return_value.status_code = 404
        with self.assertRaisesRegex(AuthError, 'AUTH_STORAGE_CONFIG'):
            store.load(TOKEN)

    def test_conflict_and_permission_fail_closed(self):
        for status in (409, 403):
            store = self.store()
            store.request = Mock(return_value=Mock(status_code=status))
            with self.assertRaisesRegex(AuthError, 'AUTH_STORAGE_WRITE'):
                store.save(TOKEN)


if __name__ == '__main__':
    unittest.main()

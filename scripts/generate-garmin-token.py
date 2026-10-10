"""Run locally with uv run python scripts/generate-garmin-token.py.

Outputs only a file path; credentials, MFA and session JSON are never printed.
"""
import getpass
import logging
import os
from pathlib import Path

from garminconnect import Garmin

for name in ('garminconnect', 'garminconnect.client'):
    logging.getLogger(name).disabled = True
os.environ.pop('GARMINTOKENS', None)
client = Garmin(
    input('Garmin email: '),
    getpass.getpass('Garmin password: '),
    prompt_mfa=lambda: getpass.getpass('MFA code (hidden): '),
)
try:
    client.login()
    destination = Path.home() / '.garminconnect' / 'garmin_tokens.json'
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(destination, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(client.client.dumps())
except Exception:
    raise SystemExit('Local authentication failed. Check credentials/MFA/network and retry.') from None
print(f'Session saved privately to {destination}. Upload using gh secret set; do not print or commit it.')

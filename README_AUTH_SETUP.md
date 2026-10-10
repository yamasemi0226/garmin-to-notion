# Garmin authentication and migration

The locked and pinned authentication implementation is `garminconnect==0.3.3`.
It uses native DI OAuth2 (`di_token`, `di_refresh_token`, `di_client_id`), not
older garth OAuth1/OAuth2 token pairs. The adapter relies on this version's
`client.loads()`, `dumps()`, `_refresh_di_token()`, `_refresh_session()` and
`_token_expires_soon()` APIs. Review the adapter and tests before upgrading.

## Why the previous workflow failed

The library retries a 401 with a refresh but suppresses refresh errors in
`_refresh_session()`. `Garmin.login()` then retries the social profile three
times and wraps the final error. A social-profile 401 alone does **not** prove
that the refresh token expired. Inline token updates previously lived only in
memory. Refresh-token rotation could leave later runners using stale secrets.

## Storage design

Sessions are Fernet encrypted with a separate key stored only in Actions
Secrets. Only ciphertext is committed to `garmin-auth-state/garmin-session.enc`.
No plaintext tokens are stored in git, cache, artifacts, logs or workflow outputs.
Each process reads the branch at execution time; queued runs therefore do not
reuse an obsolete snapshot of the bootstrap Secret. Rotation is persisted
immediately, before subsequent Garmin or Notion requests. Failed writes stop
synchronization. GitHub's contents SHA precondition rejects concurrent updates.
The workflow's repository-wide concurrency group serializes scheduled/manual
runs, across workflow refs. Use this same group for any other workflow accessing
this session. Do not run another local writer against the state simultaneously.

A response loss after Garmin rotates a token but before it can be stored cannot
be made transactional across Garmin and GitHub. A storage/network failure may
require local reauthentication if the previously saved refresh token was revoked.
Keep the encryption key: losing it makes the saved state unreadable.

## GitHub setup (existing GARMIN_AUTH_TOKEN is retained for migration)

1. Merge the authentication fix into `main`. Pause scheduled runs during setup.
2. In the repository **Code** tab, create branch **garmin-auth-state** from `main`.
   Do not run synchronization workflows from this branch. It holds encrypted state.
3. Create a GitHub **fine-grained personal access token** in account Settings →
   Developer settings → Personal access tokens → Fine-grained tokens.
   Select only `yamasemi0226/garmin-to-notion`, with repository **Contents:
   Read and write**. Set an expiration and renew it before expiration.
   The normal `GITHUB_TOKEN` is insufficient for this design (it has read only
   access). Branch rules must allow this PAT to write to `garmin-auth-state`.
4. Repository **Settings → Secrets and variables → Actions → New repository secret**:
   create **GARMIN_STATE_GITHUB_TOKEN** with that PAT.
5. Generate a Fernet key locally from the checked-out project and send it directly
   to GitHub without printing it:

   ```sh
   uv sync --frozen
   uv run --frozen python -c 'from cryptography.fernet import Fernet; import sys; sys.stdout.buffer.write(Fernet.generate_key())' | gh secret set GARMIN_STATE_KEY --repo yamasemi0226/garmin-to-notion
   ```

   `gh` must be installed and authenticated (`gh auth login`). Keep a private
   backup of the key in a password manager. Never replace the key while encrypted
   state exists without a deliberate reset.
6. Keep existing **GARMIN_AUTH_TOKEN** and all Notion Secrets as configured.
   In **Actions → Sync Garmin to Notion → Run workflow**, choose `main`.
7. Confirm `AUTH_OK` and a ciphertext file on the state branch. Run again to
   verify the persisted state is reused. An `AUTH_REFRESH_OK` line appears only
   when a refresh actually occurs. After the first successful migration, delete
   **GARMIN_AUTH_TOKEN** to remove the stale bootstrap credential.

The workflow continues to use the existing Notion databases and synchronization
modules unchanged. Do not add Garmin email, password or MFA to Actions Secrets.

## Diagnostics and when to log in again

| Code | Meaning and next action |
| --- | --- |
| `AUTH_REFRESH_OK` | Refresh succeeded and was persisted. An initial 401 that recovers indicates an access-token problem. |
| `AUTH_REFRESH_REJECTED` | Refresh endpoint returned 400/401. Local reauthentication may be needed; this does not prove expiration versus revocation. |
| `AUTH_API_REJECTED` | New access token was still rejected with 401. Check Garmin account/service first; repeated login may not fix API-side rejection. |
| `AUTH_REFRESH_FORBIDDEN` / `AUTH_API_FORBIDDEN` | 403; check network/service restrictions before reauthenticating. |
| `AUTH_REFRESH_TRANSIENT` / `AUTH_API_UNAVAILABLE` | Network/server/profile failure. Retry later; no session invalidation is inferred. |
| `AUTH_REAUTH_REQUIRED` | Missing/invalid/legacy token format; generate a native DI session locally. |
| `AUTH_STORAGE_*` | Check PAT expiry/permissions, state branch, encryption key or concurrent writes. Do not fall back to stale bootstrap. |

Diagnostics expose fixed classifications and HTTP status only. They do not print
Garmin exception bodies, JWT payloads, headers, usernames, passwords or MFA codes.
Token expiry checks are advisory; a valid-looking expiry cannot prove validity.

## Local reauthentication / deliberate reset

Only after a rejection or invalid session makes it necessary:

```sh
uv sync --frozen
uv run --frozen python scripts/generate-garmin-token.py
gh secret set GARMIN_AUTH_TOKEN --repo yamasemi0226/garmin-to-notion < "$HOME/.garminconnect/garmin_tokens.json"
```

The script prompts for email, hidden password and hidden MFA, and saves JSON to
`~/.garminconnect/garmin_tokens.json` with mode 0600. It prints only the file path.
Do not `cat` the file, paste it into chat, upload it as an artifact or commit it.

Pause workflow runs and wait for active synchronization to finish. Upload the new
bootstrap Secret, then delete **only `garmin-session.enc` on `garmin-auth-state`**
through the GitHub Code UI. Keep the branch and encryption key. Run the workflow
on `main` to seed the replacement state, confirm success, then remove the bootstrap
Secret again. Updating the bootstrap alone intentionally cannot override existing
state. Delete the local token file when no longer needed.

## Tests

```sh
uv run --frozen python -m unittest discover -s tests -v
```

Tests exercise the real pinned login/request implementation with mocked HTTP:
proactive refresh, 401 recovery, persistent 401, rejected/transient/forbidden
refresh, safe diagnostics, storage failure, encryption roundtrip, migration,
corrupt state and conflicting writes. No live Garmin credentials are required.

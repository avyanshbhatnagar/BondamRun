# Bondam Run – account API (Cloudflare Worker + D1)

Sign-up and sign-in for the game, running entirely on Cloudflare's **free plan** and reachable from a
GitHub Pages site. No domain needed: the API lives at `https://<worker>.<subdomain>.workers.dev`.

```
worker/src/index.js            the API
worker/migrations/0001_init.sql  D1 schema (users + brute-force counters)
deploy.mjs                     one-command deploy (safe to re-run)
client/auth-client.js          browser helper: hashes the password, calls the API
test/run-tests.mjs             end-to-end tests against a local worker
.env.example                   settings for deploy.mjs
```

## 1. Create the Cloudflare API token

1. Open <https://dash.cloudflare.com/profile/api-tokens> → **Create Token** → **Create Custom Token**.
2. Name it `bondam-run-deploy`.
3. **Permissions** (all at *Account* level):

   | Resource | Permission | Why |
   |---|---|---|
   | Workers Scripts | **Edit** | upload the Worker, set secrets, register the workers.dev subdomain |
   | D1 | **Edit** | create the database and run migrations |
   | Account Settings | **Read** | wrangler looks the account up |
   | Workers KV Storage | **Edit** | *optional now* – needed when you add a KV cache for the leaderboard |

4. **Account Resources**: Include → *your account only*. You do **not** need any Zone permissions (no domain).
5. (Optional) set an expiry date, e.g. 90 days. Create it and copy the token – it is shown once.
6. Your **Account ID**: dashboard → *Workers & Pages* → right-hand sidebar.

If a deploy step fails with `10000 Authentication error`, add the permission named in that step and retry.

## 2. Deploy

```bash
cp .env.example .env        # fill in CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, ALLOWED_ORIGINS
node deploy.mjs             # Node 18+; use --dry-run first if you like
```

* `ALLOWED_ORIGINS` is your GitHub Pages **origin**, no path: `https://<github-username>.github.io`
  (it is the same for every repo under that account).
* First run only: if the account has no workers.dev subdomain yet, set `WORKERS_SUBDOMAIN` to a unique name.
* The script prints the **API base URL**. Put it in `client/auth-client.js` (`API_BASE`) and publish the
  `client/` file with your game.
* Re-running is safe: the database, subdomain and secrets are never recreated or overwritten.
* It generates two secrets once (`PEPPER`, `SESSION_SECRET`) and keeps a copy in `.deploy-secrets.json`.
  **Back that file up and keep it out of git.** If `PEPPER` is lost, nobody can log in until passwords are reset.

## Put it on GitHub and let GitHub run the deploy

1. Unzip this pack into the root of your `BondamRun` clone (it adds `api/` and `.github/workflows/deploy-api.yml`; nothing is overwritten), then:
   ```bash
   git add api .github
   git commit -m "Add account API (Cloudflare Worker + D1)"
   git push
   ```
   `api/.gitignore` keeps `.env`, `.deploy-secrets.json` and `worker/.dev.vars` out of git. Check `git status` first.
2. Repo → **Settings → Secrets and variables → Actions**
   * *Secrets:* `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and two random values `PEPPER` and `SESSION_SECRET`
     (create each with `openssl rand -hex 32`; keep a copy in a password manager – GitHub will not show them again).
   * *Variables:* `ALLOWED_ORIGINS` = `https://<github-user>.github.io`, and `WORKERS_SUBDOMAIN` (first deploy only).
3. **Actions → Deploy API → Run workflow.** The log ends with the API base URL. Later pushes that touch `worker/`
   redeploy automatically.

The Cloudflare token lives only in GitHub's encrypted secrets – nobody else (including Claude) ever needs to see it.
The workflow already runs inside `api/`. GitHub Pages publishes the whole repo, so `api/` will be visible on the web; it contains no secrets (those live in GitHub/Cloudflare), but keep it that way.

## 3. Use it from the game

```js
import { register, login, me, logout, getSession, explain } from './auth-client.js';
try { await register('alice', 'correct horse battery'); } catch (e) { alert(explain(e)); }
```

## API

| Call | Body | Success | Errors |
|---|---|---|---|
| `POST /api/register` | `{username, pw}` | 201 `{token, user}` | 400 invalid_username / invalid_password_hash, 409 username_taken, 429 too_many_attempts |
| `POST /api/login` | `{username, pw}` | 200 `{token, user}` | 401 invalid_credentials, 429 too_many_attempts |
| `GET /api/me` | `Authorization: Bearer <token>` | 200 `{user, token?}` (fresh token when the old one is half-expired) | 401 unauthorized |
| `POST /api/logout-all` | Bearer | 200 `{ok}` – signs out every device | 401 |
| `GET /api/health` | – | 200 `{ok:true}` | – |

Usernames: 3–20 letters, digits or `_`, unique ignoring case. Sessions last 30 days.

## How passwords are protected

1. **In the browser:** `pw = PBKDF2-SHA256(password, salt = "bondam-run:v1:" + username, 120 000 rounds)`.
   The plain password never leaves the device.
2. **In the Worker:** the stored value is `HMAC-SHA256(PEPPER, randomSalt + ":" + pw)`.
3. **Why two layers?** The value the browser sends *is* effectively the password – whoever has it can log in.
   Storing it as-is would make a database leak equal to a password leak. The per-user salt and the secret pepper
   (kept in Worker secrets, not in D1) mean a stolen database cannot even be used to test guesses.
4. **Why the slow hashing is in the browser:** the free plan allows ~10 ms of CPU per request, too little for a
   server-side PBKDF2/bcrypt. Players' devices do the heavy part instead. `pw_algo` is stored per user, so on a
   paid plan you can switch to a heavier server hash and upgrade users silently at their next login.
5. Also: constant-time comparisons, identical answers for "wrong password" and "no such user", 8 failed logins
   per username / 30 per IP per 15 minutes, 5 sign-ups per IP per hour, CORS limited to your origin, request
   bodies capped at 2 KB, sessions can be revoked with `logout-all`.

Not included on purpose (keep it simple): password reset / email, changing username or password.
Players who forget a password currently need manual help – tell me if you want a recovery-code flow.

## Free-plan budget (limits as I know them – confirm on Cloudflare's pricing pages)

| Service | Free allowance | What auth uses |
|---|---|---|
| Workers | 100 000 requests/day, 10 ms CPU each | a few hundred µs of CPU per call |
| D1 | 5 M rows read/day, 100 k rows written/day, 5 GB | register ≈ 2 writes; login ≈ 3 reads + 1–2 writes (~50 k logins/day) |
| KV | 100 k reads/day, **1 000 writes/day** | not used yet |

The free plan never bills you; if a limit is hit, requests simply fail until the daily reset.

## Next: leaderboard, progress, challenges

* Add migrations `0002_…` with tables that reference `users(id)`:
  `progress(user_id PRIMARY KEY, data JSON, best_distance, updated_at)`,
  `scores(user_id, mode, best, updated_at, PRIMARY KEY(user_id, mode))` + an index on `(mode, best DESC)`,
  `challenges(id, from_user, to_user, mode, target, status, created_at, expires_at)`.
* Re-use `requireUser()` in `index.js` for every authenticated route; the `ROUTES` table is where you register them.
* Leaderboard reads are the likely hot path: cache the top-N JSON in **KV for ~5 minutes** (≈ 288 writes/day,
  safely under the 1 000/day limit) so most requests cost zero D1 reads.
* Keep writes small: upsert only when a score improves, send progress at the end of a run, not every frame.
* Remember that scores come from the player's browser – validate ranges server-side and expect some cheating.

## Local development and tests

```bash
cp worker/.dev.vars.example worker/.dev.vars
npm run dev:setup      # creates the local D1 tables (on disk, no Cloudflare account needed)
npm run dev            # worker on http://localhost:8787      (terminal 1)
npm test               # 26 end-to-end checks                  (terminal 2)
```

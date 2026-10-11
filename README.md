<h1 align="center">🛡️ leakroute</h1>

<p align="center">
  <strong>Catch unprotected API endpoints and leaked secrets in AI-generated code, before they ship.</strong>
</p>

<p align="center">
  <a href="https://github.com/UmutBolatbas/leakroute/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/UmutBolatbas/leakroute/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://github.com/UmutBolatbas/leakroute/releases"><img alt="Release" src="https://img.shields.io/github/v/release/UmutBolatbas/leakroute?sort=semver"></a>
  <a href="https://www.npmjs.com/package/leakroute"><img alt="npm" src="https://img.shields.io/npm/v/leakroute"></a>
</p>

leakroute is a GitHub Action and CLI that reviews every pull request for two
mistakes AI coding assistants make all the time:

1. **Endpoints without authentication**: routes that look finished, return the right data,
   and let anyone call them.
2. **Hardcoded secrets**: API keys, tokens, private keys and `.env` files committed to the repo.

It runs locally, never sends your code anywhere, and never prints a secret: findings show
at most the first four characters (`sk-p****`).

<p align="center">
  <img src="https://raw.githubusercontent.com/UmutBolatbas/leakroute/main/docs/assets/pr-comment.png" alt="leakroute commenting on a pull request: one high-risk unprotected DELETE endpoint, with why it was flagged and how to fix it" width="760">
</p>

---

## Why?

Ask an AI assistant for "an endpoint that deletes a user" and you will usually get one that
works. Whether it checks _who_ is calling it depends on whether the auth middleware happened
to be in the context window. The code compiles, the tests pass, the demo works, and the
review focuses on the business logic. The missing `requireAuth` is easy to miss because
**it is not there to see**.

The same goes for secrets. Pasting a real key "just to try it" and asking the assistant to
"make it work" is how `sk-live-...` ends up in `config.ts`.

leakroute is a second pair of eyes for exactly these two problems. Every finding says
**why** it was flagged and **how** to fix it, because static analysis can be wrong and you
should be able to judge it in seconds.

## Quick start (30 seconds)

Add `.github/workflows/leakroute.yml`:

```yaml
name: leakroute
on: [pull_request, push]

permissions:
  contents: read
  pull-requests: write # PR comment
  security-events: write # Code Scanning (Security tab)

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: UmutBolatbas/leakroute@v1
        with:
          fail-on: high
          comment-on-pr: true
          upload-sarif: true
```

That's it. On every pull request you get:

- **one PR comment** listing findings in the files the PR changed, updated in place on every push;
- **annotations** on the affected lines in the diff;
- **a job summary** table with file, line, rule, risk, explanation and suggested fix;
- **Code Scanning alerts** in the repository's _Security_ tab (SARIF 2.1.0);
- **a failed check** when something reaches the `fail-on` severity.

Or run it locally, no install needed:

```bash
npx leakroute scan .
```

```text
leakroute v1.0.0 · scanned 214 files in 812ms

routes/admin.ts
  8:1     HIGH    Possible unprotected endpoint: GET /admin/stats  endpoint/express-unprotected-route
          why: No authentication found for `GET /admin/stats`: no auth middleware on the route or
               registered before it on `app` → `/admin: adminRouter in routes/admin.ts`, and the
               handler does not call a known auth function or respond 401/403. The path contains
               `/admin`, which suggests privileged data.
          fix: Add auth middleware to the route (`router.post('/x', requireAuth, handler)`) or
               protect the whole router with `router.use(requireAuth)` before its routes. …

src/lib/openai.ts
  3:23    HIGH    Possible OpenAI API key  secret/openai-api-key
          why: Matches the documented OpenAI API key format (sk-p****). If it is a real credential,
               anyone who can read this repository can use it.
          fix: Revoke the key in the OpenAI dashboard. Revoke/rotate this credential now, then load
               it from an environment variable or a secret manager.

✖ 2 possible issues (2 high, 0 medium, 0 low)
```

## What it detects

### Unprotected endpoints

leakroute parses your code into syntax trees (not regexes), follows routers across files,
and checks whether **any** authentication applies to each route.

| Framework                  | Routes it reads                                                                  | Auth it recognizes                                                                                                                                                               |
| -------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Express**                | `app/router.get/post/put/patch/delete/all`, `router.route()`, `app.use('/x', r)` | Route middleware, `router.use()` / `app.use()` **registered before the route**, `passport.authenticate`, `express-jwt`, handlers that check the user or respond 401/403          |
| **Fastify**                | `fastify.get/post/…`, `fastify.route({...})`, `register(plugin, { prefix })`     | `onRequest` / `preHandler` route options, `addHook(...)` in the plugin chain, `fastify.auth([...])`, `request.jwtVerify()`                                                       |
| **Next.js** (App Router)   | `app/**/route.ts` (`GET`, `POST`, …), route groups, dynamic segments             | `auth()`, `getServerSession()`, `currentUser()`, `getAuth()`, Supabase `auth.getUser()`, wrappers like `withAuth(handler)`, helpers that call them, `middleware.ts` / `proxy.ts` |
| **Next.js** (Pages Router) | `pages/api/**`                                                                   | Same as above, plus `req.method` detection for the risk level                                                                                                                    |
| **FastAPI**                | `@app.get/post/…`, `api_route`, `APIRouter`, `include_router(..., prefix=)`      | `Depends(...)` / `Security(...)` on parameters, `dependencies=[...]` on the route, router, include or app, `Annotated` aliases, `OAuth2PasswordBearer` / `HTTPBearer`            |
| **Flask**                  | `@app.route`, `@bp.get/post/…`, blueprints, `register_blueprint(url_prefix=)`    | `@login_required`, `@jwt_required()`, `@auth.login_required`, custom decorators that abort 401/403, `before_request` hooks, `current_user.is_authenticated` checks               |

For Next.js, `middleware.ts` (or `proxy.ts` in Next 16) only counts when it actually
authenticates **and** its `matcher` covers the route. Path lists inside the middleware
(`protectedRoutes = ['/dashboard']`) and Clerk's `createRouteMatcher` are taken into account,
and a bare `clerkMiddleware()` is not treated as protection.

leakroute also flags a classic Flask bug: `@login_required` written **above** `@app.route`
never runs, because Flask registers the undecorated function.

**Risk levels**

| Risk       | When                                                                                                                                                          |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **high**   | Unprotected `POST`, `PUT`, `PATCH`, `DELETE` or `ALL`, or a path containing `/admin`, `/users`, `/internal`, `/billing`, `/delete`, `/settings`, `/payments`… |
| **medium** | Unprotected `GET`                                                                                                                                             |
| **low**    | Unprotected `HEAD` / `OPTIONS`                                                                                                                                |

Public by default (never reported): `/`, `/health`, `/healthz`, `/ping`, `/status`, `/version`,
`/login`, `/logout`, `/register`, `/signup`, `/forgot-password`, `/reset-password`,
`/verify-email`, `/token`, `/oauth/**`, `/api/auth/**` (NextAuth), `/public/**`, `/docs`,
`/openapi.json`, `/robots.txt`, `/favicon.ico` (also under any prefix such as `/api/v1/health`).

### Secrets

| Rule                           | Detects                                                                                                                                 | Risk   |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| `secret/aws-access-key-id`     | AWS access key IDs (`AKIA…`, `ASIA…`)                                                                                                   | high   |
| `secret/aws-secret-access-key` | AWS secret keys assigned to an `aws…secret` name                                                                                        | high   |
| `secret/openai-api-key`        | OpenAI keys (`sk-proj-…`, `sk-svcacct-…`, legacy `sk-…`)                                                                                | high   |
| `secret/anthropic-api-key`     | Anthropic keys (`sk-ant-…`)                                                                                                             | high   |
| `secret/github-token`          | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)                                                                   | high   |
| `secret/stripe-live-key`       | Stripe live secret and restricted keys (`sk_live_`, `rk_live_`)                                                                         | high   |
| `secret/slack-token`           | Slack tokens (`xoxb-`, `xoxp-`, `xapp-`, …)                                                                                             | high   |
| `secret/slack-webhook`         | Slack incoming webhook URLs                                                                                                             | medium |
| `secret/google-api-key`        | Google API keys (`AIza…`)                                                                                                               | medium |
| `secret/npm-token`             | npm access tokens (`npm_…`)                                                                                                             | high   |
| `secret/sendgrid-api-key`      | SendGrid API keys                                                                                                                       | high   |
| `secret/huggingface-token`     | Hugging Face tokens (`hf_…`)                                                                                                            | high   |
| `secret/private-key`           | PEM private key blocks (RSA, EC, OpenSSH, PGP, PKCS#8), including JSON-escaped ones                                                     | high   |
| `secret/jwt`                   | JSON Web Tokens (header must decode to a JWT header)                                                                                    | medium |
| `secret/database-url`          | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`… URLs with a password                                                | high   |
| `secret/generic-high-entropy`  | High-entropy strings assigned to names like `apiKey`, `client_secret`, `AUTH_TOKEN` (Shannon entropy)                                   | medium |
| `secret/hardcoded-password`    | String literals assigned to `password` / `pwd` names                                                                                    | medium |
| `secret/env-file`              | Committed `.env`, `.env.production`, … (`.env.example` is fine)                                                                         | high   |
| `secret/private-key-file`      | Committed `id_rsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, …                                                                      | high   |
| `secret/credentials-file`      | Committed `credentials.json`, service account JSON, `.git-credentials`, `.netrc`, `.pgpass`, `terraform.tfstate`, `.npmrc` with a token | high   |

False positives are kept down by ignoring obvious placeholders (`EXAMPLE`, `xxxx`,
`your-api-key-here`, `${VAR}`, `<TOKEN>`, `changeme`, the jwt.io sample token,
`postgres://user:password@localhost`), by only applying entropy checks to credential-like
variable names, and by skipping generic checks in test and example files.

Use `--git-history` to also scan **every commit**: a key that was "removed" in a later
commit is still in your history, and still valid until you rotate it.

## Configuration

Run `npx leakroute init` to create a commented `.leakroute.yml`, or write one yourself.
Every key is optional:

```yaml
fail-on: high # high | medium | low | none
scan:
  endpoints: true
  secrets: true
auth-middleware: # your own auth middleware / decorator / dependency names
  - requireAdmin
  - withSession
public-routes: # routes that are public on purpose (globs)
  - /api/webhooks/*
ignore-paths: # paths to skip (globs, relative to the scanned directory)
  - '**/tests/**'
  - '**/fixtures/**'
disable-rules: # rule ids or globs
  - secret/jwt
baseline: .leakroute-baseline.json # or false
git-history: false
max-file-size: 1000000 # bytes; larger files are skipped
```

| Key               | Default                    | Description                                                                                                                                                    |
| ----------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fail-on`         | `high`                     | Fail (exit code 1) when a finding has at least this severity. `none` never fails.                                                                              |
| `scan.endpoints`  | `true`                     | Run endpoint analysis.                                                                                                                                         |
| `scan.secrets`    | `true`                     | Run secret detection.                                                                                                                                          |
| `auth-middleware` | `[]`                       | Extra names that count as authentication, added to the [built-in list](src/rules/endpoints/auth.ts). Use `a.b` to match a dotted call such as `auth.required`. |
| `public-routes`   | `[]`                       | Extra glob patterns for routes that are intentionally public, added to the defaults above.                                                                     |
| `ignore-paths`    | `[]`                       | Globs to skip. `.gitignore` is always respected, and `node_modules`, lockfiles and minified files are always skipped.                                          |
| `disable-rules`   | `[]`                       | Rule ids or globs (`secret/jwt`, `endpoint/*`) to turn off.                                                                                                    |
| `baseline`        | `.leakroute-baseline.json` | Baseline file. Findings recorded there are not reported. `false` disables it.                                                                                  |
| `git-history`     | `false`                    | Also scan every commit for secrets.                                                                                                                            |
| `max-file-size`   | `1000000`                  | Skip files larger than this many bytes.                                                                                                                        |

### Silencing a finding

Add `leakroute-ignore: <reason>` in a comment on the line, or on its own line just above it.
The reason is required, so every exception is explained in the code:

```ts
// leakroute-ignore: public product catalogue, read-only
app.get('/api/products', listProducts);

const publishable = 'pk_live_…'; // leakroute-ignore: publishable key, safe in the browser
```

```python
# leakroute-ignore[endpoint/flask-unprotected-route]: health check for the load balancer
@app.get("/internal/ping")
def ping(): ...
```

`leakroute-ignore[rule-id, other/*]: reason` limits the comment to specific rules.

### Adopting it in an existing project: baselines

On a large codebase you may not want to fix everything before turning leakroute on.
Record what exists today and only new findings will be reported:

```bash
npx leakroute baseline .   # writes .leakroute-baseline.json
git add .leakroute-baseline.json
```

Baseline entries are matched by a fingerprint that does not depend on line numbers, so
unrelated edits don't resurface old findings. The file contains rule ids, file paths and
titles only, never secrets. Run `leakroute scan --no-baseline` to see everything again.

## GitHub Action reference

| Input           | Default               | Description                                                                                                          |
| --------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `path`          | `.`                   | Directory to scan, relative to the repository root.                                                                  |
| `config`        | `.leakroute.yml`      | Config file path.                                                                                                    |
| `fail-on`       | from config (`high`)  | `high`, `medium`, `low` or `none`. Overrides the config file.                                                        |
| `comment-on-pr` | `true`                | Post one PR comment about the files the PR changes, and keep it updated. Needs `pull-requests: write`.               |
| `upload-sarif`  | `true`                | Upload results to Code Scanning. Needs `security-events: write`; private repositories need GitHub Advanced Security. |
| `sarif-file`    | `leakroute.sarif`     | Where to write the SARIF report (e.g. to upload it as an artifact).                                                  |
| `annotations`   | `true`                | Show findings as annotations on the diff.                                                                            |
| `git-history`   | `false`               | Scan every commit for secrets. Use `actions/checkout` with `fetch-depth: 0`.                                         |
| `github-token`  | `${{ github.token }}` | Token for the PR comment and SARIF upload.                                                                           |

| Output                    | Description                     |
| ------------------------- | ------------------------------- |
| `findings`                | Total number of findings        |
| `high` / `medium` / `low` | Findings per severity           |
| `sarif-file`              | Absolute path of the SARIF file |

Pull requests from forks get a read-only token. leakroute then skips the comment and the
upload with a warning instead of failing; the check result and job summary still work.

## CLI reference

```text
leakroute scan [path]       Scan a directory
  -f, --format <format>     text (default) | json | sarif
  -o, --output <file>       Write the report to a file
  --fail-on <level>         high | medium | low | none
  -c, --config <file>       Config file (default: .leakroute.yml in the scanned directory)
  --git-history             Also scan every commit for secrets
  --baseline <file>         Baseline file to compare against
  --no-baseline             Report everything, ignoring the baseline
  --no-secrets              Skip secret detection
  --no-endpoints            Skip endpoint analysis
  --no-color                Plain output

leakroute baseline [path]   Record current findings in .leakroute-baseline.json
leakroute init [path]       Create a commented .leakroute.yml
```

Exit codes: `0` no finding at or above `fail-on`, `1` findings at or above `fail-on`, `2` error
(for example an invalid config).

## How it works

1. **Files**: inside a git repository, leakroute scans what git tracks plus untracked files that
   aren't ignored, which is what you are about to commit. Outside git it walks the directory and
   applies every `.gitignore`.
2. **Secrets**: provider patterns (written from each provider's public token format
   documentation), Shannon entropy on credential-like assignments, and file-name checks.
   Values are redacted the moment they are found; the internal data model has no field that
   could hold a raw secret.
3. **Endpoints**: JS/TS is parsed with
   [`typescript-estree`](https://typescript-eslint.io/packages/typescript-estree), Python with
   [tree-sitter](https://tree-sitter.github.io/) (WebAssembly, no native build). leakroute builds a
   graph of apps, routers, blueprints and plugins, links them across imports, and walks each chain
   from the app down, collecting every middleware, hook, dependency or decorator that applies to
   each route. Handlers and helpers are followed up to two calls deep.
4. **Reports**: terminal, JSON, SARIF 2.1.0, Markdown job summary, PR comment.

## Limitations

Static analysis can't see everything. leakroute reports **possible** problems and explains
its reasoning so you can judge each one quickly. It can **miss** issues or **over-report** when:

- Auth is enforced outside the code: an API gateway, a reverse proxy, a service mesh, or
  serverless/edge configuration.
- Routes or middleware are registered dynamically (loops over a route table, computed paths,
  `app[method](...)`, plugin auto-loading such as `@fastify/autoload`).
- Auth is named unusually and does nothing recognizable (no known call, no 401/403). Add the
  name to `auth-middleware`.
- Authorization is wrong rather than missing: leakroute checks that _some_ authentication runs,
  not that user A can't read user B's data.
- Frameworks and patterns not yet supported: NestJS guards, Hono, Koa, Django/DRF, Flask
  class-based views (`MethodView`), tRPC, GraphQL resolvers.
- Secrets in formats it doesn't know, split across lines or variables, encoded, or stored in
  binary files.

It does not execute your code, call your endpoints or validate keys against providers.

## Privacy

leakroute runs entirely on your machine or runner. It makes no network requests except, in
the GitHub Action, to the GitHub API for the PR comment and the SARIF upload. Secrets are never
written to logs, comments, SARIF, summaries or baselines: only the first four characters
followed by `****` (or just `****` for short values).

## Roadmap

- [ ] Optional LLM second opinion for `medium` endpoint findings (opt-in, your own API key;
      secrets and secret-bearing code are never sent)
- [ ] NestJS, Hono and Koa
- [ ] Django / Django REST Framework, Flask class-based views
- [ ] Reporting `leakroute-ignore` suppressions as SARIF suppressions
- [ ] Pre-commit hook
- [ ] More secret providers (open an issue with the token format documentation!)

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started and
[docs/adding-a-rule.md](docs/adding-a-rule.md) for a step-by-step guide to adding a secret
pattern, an auth name or a whole framework. Please report security issues privately as
described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © UmutBolatbas. Third-party components and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Product names such as AWS, OpenAI, Anthropic, GitHub, Stripe, Next.js or FastAPI are
trademarks of their respective owners and are used only to describe what leakroute
detects. leakroute is not affiliated with or endorsed by them.

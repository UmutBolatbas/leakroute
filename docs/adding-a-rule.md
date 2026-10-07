# Adding a rule

This guide walks through the most common contributions, from smallest to largest:

1. [A new secret provider](#1-a-new-secret-provider)
2. [A new sensitive file type](#2-a-new-sensitive-file-type)
3. [A new auth middleware / decorator name](#3-a-new-auth-name)
4. [A new default public route](#4-a-new-default-public-route)
5. [A new framework](#5-a-new-framework)

Whatever you add, the bar is the same: **every finding must explain why it was flagged and
how to fix it**, and there must be a fixture that proves it is reported and one that proves
lookalikes are not.

---

## 1. A new secret provider

### a. Add the pattern

Add an entry to `SECRET_PATTERNS` in [`src/rules/secrets/patterns.ts`](../src/rules/secrets/patterns.ts):

```ts
{
  id: 'secret/acme-api-key',
  title: 'Acme API key',
  severity: 'high',
  // Token format from https://docs.acme.example/api-keys
  regex: /\b(?<secret>acme_(?:live|test)_[A-Za-z0-9]{32})\b/dg,
  remediation: `Revoke the key in the Acme dashboard. ${ROTATE}`,
},
```

Requirements:

- **Write the regex from the provider's public documentation** and link it in your PR. Do not
  copy patterns from other scanners (see [CONTRIBUTING.md](../CONTRIBUTING.md#licensing-of-contributions)).
- The part that is the actual secret must be the named group `(?<secret>…)`. Only that part is
  redacted and checked against placeholders.
- Use the `d` and `g` flags (`/…/dg`): `d` gives the exact column, `g` finds every match.
- Anchor it (`\b`, a distinctive prefix, or a lookahead) so it doesn't match inside longer strings.
- **Order matters.** When two patterns match the same text, the earlier one wins, so put more
  specific formats before more generic ones (Anthropic `sk-ant-` comes before OpenAI `sk-`).
- If the format alone isn't enough, add `check(secret, groups)`. Return `false` to drop the
  match or a severity to override it. See `secret/jwt` (header must decode) and
  `secret/database-url` (local hosts are `low`).

Common placeholders (`EXAMPLE`, `xxxx`, `your-…-here`, `${VAR}`, repeated characters…) are
filtered for every pattern by [`placeholder.ts`](../src/rules/secrets/placeholder.ts).

### b. Generate a fake value for tests

Add a generator to [`tests/helpers/fake-secrets.ts`](../tests/helpers/fake-secrets.ts). **Split the
prefix** so the source file never contains a complete token:

```ts
__ACME__: 'acme' + '_live_' + pick(32),
```

### c. Add fixtures

In [`tests/fixtures/vulnerable/secrets/config.ts`](../tests/fixtures/vulnerable/secrets/config.ts),
add a line with the placeholder and an `expect:` marker:

```ts
const acme = '__ACME__'; // expect: secret/acme-api-key
```

In [`tests/fixtures/safe/secrets/config.ts`](../tests/fixtures/safe/secrets/config.ts), add a
lookalike that must **not** be reported, such as a documentation placeholder:

```ts
const acmeKey = 'acme_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
```

### d. Finish

- Add a row to the secrets table in the [README](../README.md#secrets).
- Run `npm run check`. The no-leak test automatically checks that your new secret never
  appears in any output.
- Run `npm run build:action` and commit `dist/`.

The rule's SARIF metadata is generated from the pattern; there is nothing to register.

---

## 2. A new sensitive file type

Add an entry to `SENSITIVE_FILE_RULES` in [`src/rules/secrets/files.ts`](../src/rules/secrets/files.ts).
`name` is matched against the file's basename. Use `check(content)` to avoid flagging harmless
variants (`content` is `null` for binary or very large files). Add a case to the
"sensitive files" tests in [`tests/unit/primitives.test.ts`](../tests/unit/primitives.test.ts).

---

## 3. A new auth name

If a popular library's auth middleware, decorator or dependency isn't recognized, add its name
to `DEFAULT_AUTH_NAMES` in [`src/rules/endpoints/auth.ts`](../src/rules/endpoints/auth.ts):

- a plain name (`requireAuth`) matches the last segment of a call (`requireAuth`, `x.requireAuth`);
- a dotted name (`passport.authenticate`) matches that call exactly.

Add it to the "counts as auth" list in [`tests/unit/endpoints.test.ts`](../tests/unit/endpoints.test.ts),
and make sure names that only _look_ similar still don't count (the "does not count as auth"
list). Names that only make sense for one project belong in that project's
`auth-middleware` config, not in the defaults.

---

## 4. A new default public route

Routes that are public by nature live in `DEFAULT_PUBLIC_ROUTES` in
[`src/core/risk.ts`](../src/core/risk.ts). Only add paths that are public in practically every
application; anything project-specific belongs in `public-routes` config. Update the list in the
README.

---

## 5. A new framework

Endpoint analyzers live in [`src/rules/endpoints/`](../src/rules/endpoints/) and are called from
[`index.ts`](../src/rules/endpoints/index.ts).

**JavaScript/TypeScript frameworks** get a `JsProject`: every parsed file (ESTree AST from
typescript-estree) plus `ModuleInfo` (imports, exports, module-level functions and variables).
Reuse the helpers instead of re-implementing them:

- `resolveModule` / `resolveImportedFunction` / `functionFromNode` to follow imports;
- `deepAuthEvidence` to decide whether a handler or helper authenticates;
- `assessEndpointRisk` and `ctx.isPublic` for severity and public routes.

[`express.ts`](../src/rules/endpoints/express.ts) shows the full pattern for frameworks with
routers and middleware: collect a router graph per file, link mounts across files, then walk
each chain from the app down. [`nextjs.ts`](../src/rules/endpoints/nextjs.ts) shows a
file-based routing framework.

**Python frameworks** go into [`python.ts`](../src/rules/endpoints/python.ts), which already
handles imports, scopes, decorators, includes and auth evidence for FastAPI and Flask. Add the
framework's constructors and route decorators in a small module like
[`fastapi.ts`](../src/rules/endpoints/fastapi.ts) or [`flask.ts`](../src/rules/endpoints/flask.ts).

Then:

1. Add the rule's metadata to `ENDPOINT_RULES` in [`src/rules/registry.ts`](../src/rules/registry.ts)
   (id `endpoint/<framework>-unprotected-route`).
2. Write a finding `reason` that names what was checked (route, router chain, handler) and a
   `remediation` with a framework-specific code example.
3. Add `tests/fixtures/vulnerable/<framework>/` with `expect:` markers and
   `tests/fixtures/safe/<framework>/` covering every way the framework can be protected, then add
   the name to the `describe.each` lists in [`tests/unit/endpoints.test.ts`](../tests/unit/endpoints.test.ts).
4. As a sanity check, delete the protection from each safe route one at a time and confirm it
   gets reported.
5. Update the frameworks table and the limitations section in the README.

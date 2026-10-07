# Contributing to leakroute

Thanks for helping! Bug reports, false positive/negative reports, new secret patterns and
new framework support are all welcome.

## Reporting false positives and false negatives

These are the most useful issues you can open. Please include:

- a **minimal** code snippet that reproduces it (route definition, middleware, how it's mounted);
- what leakroute reported (or didn't);
- for secrets: the provider and a link to its token format documentation.

**Never paste a real secret** into an issue, even a revoked one. Replace it with a fake value
of the same shape.

## Development setup

You need Node.js 22 or newer (the published CLI runs on Node 20+, but the dev tooling needs 22).

```bash
git clone https://github.com/UmutBolatbas/leakroute.git
cd leakroute
npm ci
npm run check          # typecheck, lint, format check, build, tests
```

Useful scripts:

| Script                   | What it does                                              |
| ------------------------ | --------------------------------------------------------- |
| `npm test`               | Run the Vitest suite                                      |
| `npm run test:watch`     | Tests in watch mode                                       |
| `npm run build`          | Compile the CLI and library to `lib/`                     |
| `npm run build:action`   | Bundle the GitHub Action into `dist/` (commit the result) |
| `npm run lint`           | ESLint                                                    |
| `npm run format`         | Prettier                                                  |
| `node lib/cli.js scan .` | Run your local build (after `npm run build`)              |

## Project layout

```text
src/
  cli.ts, cli/program.ts      CLI entry and commands
  action.ts                   GitHub Action entry
  core/                       config, file discovery, scanner pipeline, risk, suppressions, baseline
  parsers/                    JS/TS (typescript-estree) and Python (tree-sitter WASM) helpers
  rules/secrets/              provider patterns, entropy, sensitive files, placeholders
  rules/endpoints/            express/fastify, nextjs, fastapi/flask (python.ts), auth names
  rules/registry.ts           rule metadata (used by SARIF)
  reporters/                  terminal, json, sarif, job summary, PR comment
  github/                     GitHub API calls (changed files, PR comment, SARIF upload)
tests/
  unit/, integration/         Vitest tests
  fixtures/vulnerable/<x>/    code that MUST be reported; lines carry `expect: <rule-id>` markers
  fixtures/safe/<x>/          code that must NOT be reported
  helpers/                    fixture loader and fake secret generator
vendor/grammars/              vendored tree-sitter-python.wasm (+ license, checksum)
dist/                         bundled action (generated, committed)
```

## Tests and fixtures

Every rule has a **vulnerable** fixture (must be reported) and a **safe** fixture (must not be).
In vulnerable fixtures, each line that must be reported carries a marker comment:

```ts
router.delete('/users/:id', handler); // expect: endpoint/express-unprotected-route
```

The test compares the reported `rule@line` pairs with the markers exactly, so both missed
findings and extra findings fail the test.

**Fake secrets are generated at test time.** Vulnerable secret fixtures contain placeholders
like `__STRIPE__`, which `tests/helpers/fake-secrets.ts` replaces with a generated value in a
temporary directory. Never commit a string in a real provider format, even a fake one: GitHub
push protection may block the push, and our own self-scan would flag it. Build prefixes from
parts (`'sk' + '_live_'`) if you need one in a test.

Before opening a PR, run `npm run check`. If you changed anything under `src/`, also run
`npm run build:action` and commit `dist/`; CI fails when `dist/` is out of date.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(secrets): …`,
  `fix(endpoints): …`, `docs: …`, `test: …`.
- Keep PRs focused: one rule or one fix per PR is ideal.
- Add or update fixtures for any behavior change, and update the README tables if you add
  a rule or framework.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change
  or have the right to submit it under the project's license.

## Licensing of contributions

leakroute is MIT licensed. By contributing, you agree that your contribution is licensed under
the same [MIT License](LICENSE) (inbound = outbound).

Please do not copy code, patterns or rules from other projects unless their license is
compatible with MIT **and** you keep their notice (add it to `THIRD_PARTY_NOTICES.md`). In
particular, do not copy from copyleft-licensed tools (GPL/AGPL) or from rule sets with
non-open-source licenses. Writing a pattern from a provider's public documentation is the
preferred way; link that documentation in your PR.

## Code of conduct

Be kind and assume good intent. Harassment or discrimination of any kind is not tolerated.
Report problems privately to the maintainer via GitHub.

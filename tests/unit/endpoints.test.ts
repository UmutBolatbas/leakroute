import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultConfig, type ResolvedConfig } from '../../src/core/config.js';
import {
  assessEndpointRisk,
  createPublicRouteMatcher,
  normalizeRoutePath,
} from '../../src/core/risk.js';
import { createAuthMatcher } from '../../src/rules/endpoints/auth.js';
import type { Finding } from '../../src/core/types.js';
import { allExpectedMarkers, materialize, scanDir } from '../helpers/fixtures.js';

const endpointsOnly = (extra: Partial<ResolvedConfig> = {}): Partial<ResolvedConfig> => ({
  scan: { endpoints: true, secrets: false },
  ...extra,
});

async function scanFixture(
  dir: string,
  extra: Partial<ResolvedConfig> = {},
  setup?: (root: string) => void,
) {
  const fx = materialize(dir);
  try {
    setup?.(fx.dir);
    return {
      findings: await scanDir(fx.dir, endpointsOnly(extra)),
      markers: allExpectedMarkers(fx.dir),
    };
  } finally {
    fx.cleanup();
  }
}

const id = (f: Finding) => `${f.file}:${f.ruleId}@${f.line}`;
const byTitle = (findings: Finding[], title: string) =>
  findings.find((f) => f.title.endsWith(title));

describe.each(['express', 'express-patterns', 'fastify', 'nextjs', 'nextjs-clerk'])(
  'vulnerable/%s',
  (fixture) => {
    it('reports exactly the marked routes', async () => {
      const { findings, markers } = await scanFixture(`vulnerable/${fixture}`);
      expect(markers.length).toBeGreaterThan(0);
      expect(findings.map(id).sort()).toEqual(markers.sort());
    });
  },
);

describe.each(['express', 'fastify', 'nextjs', 'nextjs-clerk'])('safe/%s', (fixture) => {
  it('reports nothing', async () => {
    const { findings } = await scanFixture(`safe/${fixture}`);
    expect(findings.map((f) => `${id(f)} ${f.title}`)).toEqual([]);
  });
});

describe('express details', () => {
  it('resolves mount prefixes across files and assigns risk', async () => {
    const { findings } = await scanFixture('vulnerable/express');
    expect(byTitle(findings, 'POST /api/feedback')?.severity).toBe('high');
    expect(byTitle(findings, 'GET /api/products')?.severity).toBe('medium');
    expect(byTitle(findings, 'GET /admin/stats')?.severity).toBe('high');
    expect(byTitle(findings, 'DELETE /admin/users/:id')).toBeDefined();
    expect(byTitle(findings, 'PUT /api/users/:id')).toBeDefined();
  });

  it('explains which router chain was checked', async () => {
    const { findings } = await scanFixture('vulnerable/express');
    const reason = byTitle(findings, 'GET /admin/stats')?.reason ?? '';
    expect(reason).toContain('`app` → `/admin: adminRouter in routes/admin.ts`');
  });

  it('accepts custom middleware names from config', async () => {
    const write = (root: string) =>
      writeFileSync(
        path.join(root, 'custom.ts'),
        [
          "import express from 'express';",
          "import { withTenant } from './tenant';",
          'const app = express();',
          "app.post('/api/invoices', withTenant, (_req, res) => res.sendStatus(201));",
        ].join('\n'),
      );
    const without = await scanFixture('safe/express', {}, write);
    expect(without.findings.map((f) => f.title)).toContain(
      'Possible unprotected endpoint: POST /api/invoices',
    );

    const withName = await scanFixture('safe/express', { authMiddleware: ['withTenant'] }, write);
    expect(withName.findings).toEqual([]);
  });

  it('accepts custom public routes from config', async () => {
    const { findings } = await scanFixture('vulnerable/express', {
      publicRoutes: ['/api/products'],
    });
    expect(byTitle(findings, 'GET /api/products')).toBeUndefined();
    expect(byTitle(findings, 'POST /api/feedback')).toBeDefined();
  });
});

describe('next.js details', () => {
  it('explains why middleware did not count', async () => {
    const { findings } = await scanFixture('vulnerable/nextjs');
    const users = byTitle(findings, 'POST /api/users');
    expect(users?.severity).toBe('high');
    expect(users?.reason).toContain('only protects `/dashboard`, `/settings`');

    const clerk = await scanFixture('vulnerable/nextjs-clerk');
    expect(clerk.findings[0]?.reason).toContain('does not appear to check authentication');
  });

  it('strips route groups and ignores private folders', async () => {
    const { findings } = await scanFixture('vulnerable/nextjs');
    expect(byTitle(findings, 'GET /api/reports')).toBeDefined();
    expect(findings.some((f) => f.file.includes('_private'))).toBe(false);
  });

  it('reads the HTTP method of pages/api handlers', async () => {
    const { findings } = await scanFixture('vulnerable/nextjs');
    expect(byTitle(findings, 'POST /api/admin/export')?.severity).toBe('high');
  });
});

describe('robustness', () => {
  it('skips files that do not parse and reports them', async () => {
    const { findings } = await scanFixture('safe/express', {}, (root) =>
      writeFileSync(path.join(root, 'broken.ts'), 'const = = ;'),
    );
    expect(findings).toEqual([]);
  });

  it('does not analyze endpoints in test files', async () => {
    const { findings } = await scanFixture('safe/express', {}, (root) =>
      writeFileSync(
        path.join(root, 'server.test.ts'),
        "import express from 'express';\nconst app = express();\napp.post('/api/x', (_q, r) => r.end());\n",
      ),
    );
    expect(findings).toEqual([]);
  });

  it('can be disabled', async () => {
    const { findings } = await scanFixture('vulnerable/express', {
      scan: { endpoints: false, secrets: false },
    });
    expect(findings).toEqual([]);
  });

  it('uses the default config shape', () => {
    expect(defaultConfig().scan.endpoints).toBe(true);
  });
});

describe('auth name matcher', () => {
  const isAuth = createAuthMatcher(['withSession']);

  it.each([
    'requireAuth',
    'passport.authenticate',
    'fastify.authenticate',
    'auth.required',
    'jwtMiddleware.verify',
    'ensureUser',
    'requireApiKey',
    'adminGuard',
    'withSession',
    'login_required',
    'supabase.auth.getUser',
  ])('%s counts as auth', (name) => expect(isAuth(name)).toBe(true));

  it.each([
    'session',
    'express.json',
    'cors',
    'helmet',
    'rateLimit',
    'auth.optional',
    'checkUserExists',
    'getUser',
    'jwt.sign',
    'validateBody',
  ])('%s does not count as auth', (name) => expect(isAuth(name)).toBe(false));
});

describe('risk', () => {
  it('normalizes route parameters across frameworks', () => {
    expect(normalizeRoutePath('/api/users/:id')).toBe('/api/users/*');
    expect(normalizeRoutePath('/api/users/[id]')).toBe('/api/users/*');
    expect(normalizeRoutePath('/api/files/[...path]')).toBe('/api/files/**');
    expect(normalizeRoutePath('/items/{item_id}/')).toBe('/items/*');
  });

  it('treats auth and health endpoints as public', () => {
    const isPublic = createPublicRouteMatcher(['/api/webhooks/*']);
    for (const p of [
      '/health',
      '/api/health',
      '/login',
      '/api/auth/[...nextauth]',
      '/api/webhooks/stripe',
    ]) {
      expect(isPublic(p), p).toBe(true);
    }
    for (const p of ['/api/users', '/admin', '/api/webhooks/stripe/replay']) {
      expect(isPublic(p), p).toBe(false);
    }
  });

  it('rates writes and sensitive paths high, reads medium', () => {
    expect(assessEndpointRisk('POST', '/api/comments').severity).toBe('high');
    expect(assessEndpointRisk('GET', '/api/admin/stats').severity).toBe('high');
    expect(assessEndpointRisk('GET', '/api/comments').severity).toBe('medium');
    expect(assessEndpointRisk('OPTIONS', '/api/comments').severity).toBe('low');
  });
});

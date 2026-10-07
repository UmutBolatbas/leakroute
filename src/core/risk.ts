import picomatch from 'picomatch';
import type { Severity } from './types.js';

/**
 * Routes that are public by nature. Matched against the normalized path
 * (lowercase, no trailing slash, parameters replaced by `*`).
 */
export const DEFAULT_PUBLIC_ROUTES: readonly string[] = [
  '/',
  '**/health',
  '**/healthz',
  '**/healthcheck',
  '**/livez',
  '**/readyz',
  '**/ping',
  '**/status',
  '**/version',
  '**/login',
  '**/signin',
  '**/sign-in',
  '**/logout',
  '**/signout',
  '**/sign-out',
  '**/register',
  '**/signup',
  '**/sign-up',
  '**/forgot-password',
  '**/reset-password',
  '**/verify-email',
  // OAuth2 password-flow token endpoint (FastAPI docs use `/token`).
  '**/token',
  '**/oauth/**',
  '**/auth/callback/**',
  '/api/auth/**',
  '**/public/**',
  '/robots.txt',
  '/sitemap.xml',
  '/favicon.ico',
  '**/docs',
  '**/openapi.json',
  '**/swagger',
  '**/swagger/**',
];

/** Path segments that suggest the endpoint touches privileged data or operations. */
const SENSITIVE_SEGMENT =
  /^(?:admin|administrator|superuser|staff|internal|private|users?|accounts?|members?|billing|payments?|invoices?|subscriptions?|delete|remove|destroy|purge|settings|secrets?|keys|tokens|credentials|roles?|permissions?|export|backup|debug|config|impersonate|manage|management)$/i;

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE', 'ALL']);

export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'HEAD'
  | 'OPTIONS'
  /** Registered for every method (`app.all`, `fastify.all`). */
  | 'ALL'
  /** Method unknown, e.g. a Next.js pages/api handler with no `req.method` check. */
  | 'ANY';

export interface Risk {
  severity: Severity;
  /** Human-readable explanation of the severity. */
  why: string;
}

/** Replaces `:id`, `[id]`, `[...slug]`, `{id}`, `<id>` with `*`. */
export function normalizeRoutePath(routePath: string): string {
  const cleaned = routePath
    .toLowerCase()
    .replace(/\[\[?\.\.\.[^\]]+\]?\]/g, '**')
    .replace(/:[\w]+[?*+]?|\[[^\]]+\]|\{[^}]+\}|<[^>]+>/g, '*')
    .replace(/\/{2,}/g, '/')
    .replace(/(.)\/$/, '$1');
  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
}

export function createPublicRouteMatcher(extra: readonly string[]): (routePath: string) => boolean {
  const patterns = [...DEFAULT_PUBLIC_ROUTES, ...extra].map((p) => p.toLowerCase());
  const isMatch = picomatch(patterns, { dot: true });
  return (routePath) => {
    const normalized = normalizeRoutePath(routePath);
    return isMatch(normalized) || isMatch(`${normalized}/`);
  };
}

export function assessEndpointRisk(method: HttpMethod, routePath: string): Risk {
  const sensitive = normalizeRoutePath(routePath)
    .split('/')
    .find((segment) => SENSITIVE_SEGMENT.test(segment));

  if (MUTATING.has(method)) {
    const verb = method === 'ALL' ? 'It accepts every HTTP method, including' : `${method}`;
    return {
      severity: 'high',
      why:
        method === 'ALL'
          ? `${verb} ones that modify data.`
          : `${verb} requests usually modify data.`,
    };
  }
  if (sensitive) {
    return {
      severity: 'high',
      why: `The path contains \`/${sensitive}\`, which suggests privileged data.`,
    };
  }
  if (method === 'HEAD' || method === 'OPTIONS') {
    return { severity: 'low', why: `${method} requests rarely expose data.` };
  }
  if (method === 'ANY') {
    return {
      severity: 'medium',
      why: 'The handler does not restrict the HTTP method, so it may also accept writes.',
    };
  }
  return { severity: 'medium', why: 'Unauthenticated reads can expose data.' };
}

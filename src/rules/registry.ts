import type { Category, Severity } from '../core/types.js';
import { SENSITIVE_FILE_RULES } from './secrets/files.js';
import { SECRET_PATTERNS } from './secrets/patterns.js';

export interface RuleMeta {
  id: string;
  category: Category;
  /** Short title shown in Code Scanning. */
  title: string;
  description: string;
  defaultSeverity: Severity;
}

export const DOCS_URL = 'https://github.com/UmutBolatbas/leakroute#rules';

const ENDPOINT_RULES: readonly RuleMeta[] = (
  [
    {
      id: 'endpoint/express-unprotected-route',
      title: 'Express route without authentication',
      description:
        'An Express route with no recognizable auth middleware on the route, on its router chain before it, or inside the handler.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/fastify-unprotected-route',
      title: 'Fastify route without authentication',
      description:
        'A Fastify route with no auth hook (onRequest/preHandler) on the route or on the plugins that register it, and no check inside the handler.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/nextjs-unprotected-route',
      title: 'Next.js route handler without authentication',
      description:
        'An app router route handler (route.ts) that does not check the session and is not covered by an authenticating middleware.ts / proxy.ts.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/nextjs-unprotected-api-route',
      title: 'Next.js API route without authentication',
      description:
        'A pages/api handler that does not check the session and is not covered by an authenticating middleware.ts / proxy.ts.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/fastapi-unprotected-route',
      title: 'FastAPI route without authentication',
      description:
        'A FastAPI path operation with no auth dependency on the route, its parameters, its router, or where the router is included.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/flask-unprotected-route',
      title: 'Flask route without authentication',
      description:
        'A Flask view with no auth decorator, no authenticating before_request hook on its blueprint or app, and no check inside the view.',
      defaultSeverity: 'high',
    },
    {
      id: 'endpoint/flask-auth-decorator-order',
      title: 'Flask auth decorator above the route decorator',
      description:
        'An auth decorator placed above @app.route never runs, because Flask registers the function it receives, which is the undecorated one.',
      defaultSeverity: 'high',
    },
  ] satisfies Omit<RuleMeta, 'category'>[]
).map((r) => ({ ...r, category: 'endpoint' as const }));

const GENERIC_SECRET_RULES: readonly RuleMeta[] = [
  {
    id: 'secret/generic-high-entropy',
    category: 'secret',
    title: 'Hardcoded secret',
    description:
      'A high-entropy string literal assigned to a variable whose name suggests a credential (key, secret, token...).',
    defaultSeverity: 'medium',
  },
  {
    id: 'secret/hardcoded-password',
    category: 'secret',
    title: 'Hardcoded password',
    description: 'A string literal assigned to a variable whose name suggests a password.',
    defaultSeverity: 'medium',
  },
];

function buildRegistry(): Map<string, RuleMeta> {
  const rules = new Map<string, RuleMeta>();
  const add = (rule: RuleMeta) => {
    if (!rules.has(rule.id)) rules.set(rule.id, rule);
  };
  ENDPOINT_RULES.forEach(add);
  for (const p of SECRET_PATTERNS) {
    add({
      id: p.id,
      category: 'secret',
      title: p.title,
      description: `A value matching the format of a ${p.title}. ${p.remediation}`,
      defaultSeverity: p.severity,
    });
  }
  GENERIC_SECRET_RULES.forEach(add);
  for (const f of SENSITIVE_FILE_RULES) {
    add({
      id: f.id,
      category: 'secret',
      title: f.id === 'secret/credentials-file' ? 'Committed credentials file' : f.title,
      description: `A file that normally holds credentials is committed to the repository. ${f.remediation}`,
      // The first rule for an id wins, and the credentials-file rules list the high one first.
      defaultSeverity: f.severity,
    });
  }
  return rules;
}

export const RULES: ReadonlyMap<string, RuleMeta> = buildRegistry();

export function ruleMeta(id: string): RuleMeta {
  return (
    RULES.get(id) ?? {
      id,
      category: id.startsWith('endpoint/') ? 'endpoint' : 'secret',
      title: id,
      description: id,
      defaultSeverity: 'medium',
    }
  );
}

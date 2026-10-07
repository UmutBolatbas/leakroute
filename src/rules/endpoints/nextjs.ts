import { fingerprint } from '../../core/fingerprint.js';
import { assessEndpointRisk, type HttpMethod } from '../../core/risk.js';
import type { Finding } from '../../core/types.js';
import {
  dottedName,
  isFunctionNode,
  lastSegment,
  position,
  stringValue,
  unwrap,
  walk,
  type Node,
  type ParsedJs,
  type TSESTree,
} from '../../parsers/javascript.js';
import { deepAuthEvidence, functionFromNode } from './evidence.js';
import { propertyValue } from './express.js';
import type { ModuleInfo } from './modules.js';
import type { EndpointContext, JsProject } from './types.js';

/**
 * Next.js route handlers (`app/**\/route.ts`) and API routes (`pages/api/**`).
 *
 * A route counts as protected when its handler authenticates (directly or via a
 * helper), or when `middleware.ts` / `proxy.ts` authenticates and its matcher
 * covers the route.
 */

const APP_ROUTE = /^(?<root>(?:.+\/)?)(?:src\/)?app\/(?<route>(?:.+\/)?)route\.[cm]?[jt]sx?$/;
const PAGES_API = /^(?<root>(?:.+\/)?)(?:src\/)?pages\/(?<route>api(?:\/.+)?)\.[cm]?[jt]sx?$/;
const MIDDLEWARE = /^(?:middleware|proxy)\.[cm]?[jt]s$/;

const APP_METHODS: readonly HttpMethod[] = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
];

const NEXT_DOCS_NOTE =
  'Prefer checking auth inside the handler even when middleware covers the route: middleware can be misconfigured or bypassed (see CVE-2025-29927).';

interface MiddlewareInfo {
  file: string;
  /** Why we believe the middleware authenticates, or `null` if it doesn't seem to. */
  evidence: string | null;
  covers: (routePath: string) => boolean;
  /** Explains coverage limits, e.g. "only protects /dashboard". */
  scopeNote: string | null;
}

export function analyzeNextjs(project: JsProject, ctx: EndpointContext): Finding[] {
  const middlewareCache = new Map<string, MiddlewareInfo | null>();
  const middlewareFor = (root: string): MiddlewareInfo | null => {
    if (!middlewareCache.has(root)) middlewareCache.set(root, findMiddleware(project, ctx, root));
    return middlewareCache.get(root) ?? null;
  };

  const findings: Finding[] = [];
  for (const parsed of project.files) {
    const file = parsed.file.path;
    const info = project.modules.get(file);
    if (!info) continue;

    const app = APP_ROUTE.exec(file);
    if (app?.groups) {
      const routePath = appRoutePath(app.groups.route ?? '');
      if (routePath === null) continue;
      findings.push(
        ...analyzeAppRoute(
          project,
          ctx,
          parsed,
          info,
          routePath,
          middlewareFor(app.groups.root ?? ''),
        ),
      );
      continue;
    }
    const pages = PAGES_API.exec(file);
    if (pages?.groups) {
      const routePath = pagesRoutePath(pages.groups.route ?? '');
      const finding = analyzePagesApi(
        project,
        ctx,
        parsed,
        info,
        routePath,
        middlewareFor(pages.groups.root ?? ''),
      );
      if (finding) findings.push(finding);
    }
  }
  return findings;
}

function analyzeAppRoute(
  project: JsProject,
  ctx: EndpointContext,
  parsed: ParsedJs,
  info: ModuleInfo,
  routePath: string,
  middleware: MiddlewareInfo | null,
): Finding[] {
  const file = parsed.file.path;
  if (ctx.isPublic(routePath)) return [];
  const out: Finding[] = [];

  for (const method of APP_METHODS) {
    const exported = info.exports.get(method);
    if (!exported) continue;
    if (handlerEvidence(project, ctx, file, exported)) continue;
    if (middleware?.evidence && middleware.covers(routePath)) continue;

    const ruleId = 'endpoint/nextjs-unprotected-route';
    const risk = assessEndpointRisk(method, routePath);
    out.push({
      ruleId,
      category: 'endpoint',
      severity: risk.severity,
      file,
      ...position(exportLocation(parsed, method) ?? exported),
      title: `Possible unprotected endpoint: ${method} ${routePath}`,
      reason: [
        `No authentication found for \`${method} ${routePath}\`: the \`${method}\` handler does not call a known auth function (such as \`auth()\`, \`getServerSession()\` or \`currentUser()\`) or respond 401/403,`,
        `and ${describeMiddleware(middleware, routePath)}.`,
        risk.why,
      ].join(' '),
      remediation: `Check the session at the top of the handler, e.g. \`const session = await auth(); if (!session) return new Response('Unauthorized', { status: 401 });\`. ${NEXT_DOCS_NOTE} If the route is meant to be public, add it to \`public-routes\` in .leakroute.yml.`,
      fingerprint: fingerprint(ruleId, file, method, routePath),
    });
  }
  return out;
}

function analyzePagesApi(
  project: JsProject,
  ctx: EndpointContext,
  parsed: ParsedJs,
  info: ModuleInfo,
  routePath: string,
  middleware: MiddlewareInfo | null,
): Finding | null {
  const file = parsed.file.path;
  const exported = info.exports.get('default');
  if (!exported || ctx.isPublic(routePath)) return null;
  if (handlerEvidence(project, ctx, file, exported)) return null;
  if (middleware?.evidence && middleware.covers(routePath)) return null;

  const resolved = functionFromNode(project, file, exported);
  const methods = resolved ? comparedMethods(resolved.fn) : [];
  const method: HttpMethod =
    methods.find((m) => m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS') ?? methods[0] ?? 'ANY';
  const label = methods.length > 0 ? methods.join(', ') : 'ANY';

  const ruleId = 'endpoint/nextjs-unprotected-api-route';
  const risk = assessEndpointRisk(method, routePath);
  const exportNode = parsed.ast.body.find((s) => s.type === 'ExportDefaultDeclaration') ?? exported;
  return {
    ruleId,
    category: 'endpoint',
    severity: risk.severity,
    file,
    ...position(exportNode),
    title: `Possible unprotected endpoint: ${label} ${routePath}`,
    reason: [
      `No authentication found for \`${routePath}\`: the API route handler does not call a known auth function (such as \`getServerSession()\` or \`getAuth()\`) or respond 401/403,`,
      `and ${describeMiddleware(middleware, routePath)}.`,
      risk.why,
    ].join(' '),
    remediation: `Check the session at the top of the handler, e.g. \`const session = await getServerSession(req, res, authOptions); if (!session) return res.status(401).end();\`. ${NEXT_DOCS_NOTE} If the route is meant to be public, add it to \`public-routes\` in .leakroute.yml.`,
    fingerprint: fingerprint(ruleId, file, routePath),
  };
}

/** Evidence that an exported handler authenticates: directly, via a wrapper, or via a helper. */
function handlerEvidence(
  project: JsProject,
  ctx: EndpointContext,
  file: string,
  exported: Node,
): string | null {
  const n = unwrap(exported);
  if (n.type === 'CallExpression') {
    // export const GET = withAuth(async (req) => {...})
    const wrapper = dottedName(n.callee);
    if (wrapper && ctx.isAuth(wrapper)) return `is wrapped in \`${wrapper}()\``;
    // A custom wrapper that authenticates: export const POST = withUser(handler)
    const wrapperFn = functionFromNode(project, file, n.callee);
    if (wrapperFn) {
      const evidence = deepAuthEvidence(project, wrapperFn.file, wrapperFn.fn, ctx.isAuth);
      if (evidence) return `is wrapped in a function that ${evidence}`;
    }
  }
  const resolved = functionFromNode(project, file, exported);
  return resolved ? deepAuthEvidence(project, resolved.file, resolved.fn, ctx.isAuth) : null;
}

/** HTTP methods a pages/api handler compares `req.method` against. */
function comparedMethods(fn: Node): HttpMethod[] {
  const found = new Set<HttpMethod>();
  const add = (node: Node | null | undefined) => {
    const value = stringValue(node)?.toUpperCase();
    if (value && (APP_METHODS as readonly string[]).includes(value)) found.add(value as HttpMethod);
  };
  walk(fn, (node) => {
    if (node.type === 'BinaryExpression' && /^[!=]==?$/.test(node.operator)) {
      const isMethod = (x: Node) => lastSegment(dottedName(x) ?? '') === 'method';
      if (isMethod(node.left)) add(node.right);
      if (isMethod(node.right)) add(node.left);
    } else if (
      node.type === 'SwitchStatement' &&
      lastSegment(dottedName(node.discriminant) ?? '') === 'method'
    ) {
      for (const c of node.cases) add(c.test);
    }
    return undefined;
  });
  return [...found];
}

// ---- middleware ---------------------------------------------------------

function findMiddleware(
  project: JsProject,
  ctx: EndpointContext,
  root: string,
): MiddlewareInfo | null {
  const candidates = project.files.filter((f) => {
    const rel = f.file.path.slice(root.length);
    if (!f.file.path.startsWith(root)) return false;
    const inSrc = rel.startsWith('src/') ? rel.slice(4) : rel;
    return MIDDLEWARE.test(inSrc) && !inSrc.includes('/');
  });
  const parsed = candidates[0];
  const info = parsed ? project.modules.get(parsed.file.path) : undefined;
  if (!parsed || !info) return null;
  const file = parsed.file.path;

  const exported =
    info.exports.get('default') ?? info.exports.get('middleware') ?? info.exports.get('proxy');
  const matchers = readMatchers(info);
  const inMatcher = (p: string) =>
    matchers === null || matchers.some((re) => re.test(samplePath(p)));
  const result: MiddlewareInfo = { file, evidence: null, covers: inMatcher, scopeNote: null };
  if (!exported) return result;

  const n = unwrap(exported);
  let body: Node | null = null;

  if (n.type === 'Identifier' && info.imports.has(n.name)) {
    // export { auth as middleware } from '@/auth'
    const ref = info.imports.get(n.name);
    if (ref && (ctx.isAuth(ref.name) || ctx.isAuth(n.name)))
      result.evidence = `re-exports \`${ref.name}\``;
  } else if (n.type === 'CallExpression') {
    const callee = dottedName(n.callee) ?? '';
    const callback = n.arguments.map((a) => unwrap(a)).find(isFunctionNode) ?? null;
    if (lastSegment(callee) === 'clerkMiddleware') {
      // clerkMiddleware() alone only attaches auth state; routes are protected by auth.protect().
      body = callback;
      if (callback && findCall(callback, (name) => lastSegment(name) === 'protect')) {
        result.evidence = 'calls `auth.protect()` in `clerkMiddleware`';
      }
    } else if (ctx.isAuth(callee)) {
      result.evidence = `is wrapped in \`${callee}()\``;
      body = callback;
    } else {
      body = callback;
    }
  }

  const resolved = body ? { fn: body, file } : functionFromNode(project, file, exported);
  if (!result.evidence && resolved) {
    result.evidence =
      deepAuthEvidence(project, resolved.file, resolved.fn, ctx.isAuth) ??
      redirectsToLogin(resolved.fn);
  }

  if (result.evidence && resolved) {
    const scope = readScope(resolved.fn, info);
    if (scope) {
      result.covers = (p) => inMatcher(p) && scope.covers(p);
      result.scopeNote = scope.note;
    }
  }
  return result;
}

function describeMiddleware(middleware: MiddlewareInfo | null, routePath: string): string {
  if (!middleware) return 'there is no `middleware.ts` / `proxy.ts`';
  if (!middleware.evidence) return `\`${middleware.file}\` does not appear to check authentication`;
  if (middleware.scopeNote)
    return `\`${middleware.file}\` ${middleware.scopeNote}, which does not include \`${routePath}\``;
  return `the \`matcher\` in \`${middleware.file}\` does not cover \`${routePath}\``;
}

/** Login redirects are a strong sign of a hand-written auth check. */
function redirectsToLogin(fn: Node): string | null {
  let redirects = false;
  let loginPath = false;
  walk(fn, (node) => {
    if (node.type === 'CallExpression' && lastSegment(dottedName(node.callee) ?? '') === 'redirect')
      redirects = true;
    const value = stringValue(node);
    if (value && /^\/(?:auth\/)?(?:login|signin|sign-in)\b/i.test(value)) loginPath = true;
    return undefined;
  });
  return redirects && loginPath ? 'redirects to a login page' : null;
}

function findCall(fn: Node, test: (name: string) => boolean): boolean {
  let found = false;
  walk(fn, (node) => {
    if (found) return false;
    if (node.type === 'CallExpression') {
      const name = dottedName(node.callee);
      if (name && test(name)) found = true;
    }
    return undefined;
  });
  return found;
}

/** `export const config = { matcher: [...] }` -> regexes, or `null` for "every path". */
function readMatchers(info: ModuleInfo): RegExp[] | null {
  const config = info.exports.get('config');
  if (!config || unwrap(config).type !== 'ObjectExpression') return null;
  const matcher = propertyValue(unwrap(config) as TSESTree.ObjectExpression, 'matcher');
  if (!matcher) return null;

  const m = unwrap(matcher);
  const entries = m.type === 'ArrayExpression' ? m.elements : [m];
  const patterns = entries.flatMap((e) => {
    if (!e || e.type === 'SpreadElement') return [];
    const el = unwrap(e);
    if (el.type === 'ObjectExpression') {
      const source = stringValue(propertyValue(el, 'source'));
      return source ? [source] : [];
    }
    const value = stringValue(el);
    return value ? [value] : [];
  });
  if (patterns.length === 0) return null;
  return patterns.map(nextPatternToRegex);
}

/**
 * Converts a Next.js matcher / Clerk route pattern (path-to-regexp syntax) to a RegExp.
 * Unparseable patterns match everything, so we err on the side of fewer false positives.
 */
export function nextPatternToRegex(pattern: string): RegExp {
  const source = pattern
    .replace(/\/:\w+\*/g, '(?:/.*)?')
    .replace(/\/:\w+\+/g, '/.+')
    .replace(/\/:\w+\?/g, '(?:/[^/]+)?')
    .replace(/:\w+(\([^)]*\))?/g, (_m, group: string | undefined) => group ?? '[^/]+');
  try {
    return new RegExp(`^${source}$`);
  } catch {
    return /^/;
  }
}

/**
 * Many middlewares only guard some paths:
 *   const protectedRoutes = ['/dashboard', '/settings'];
 *   if (protectedRoutes.some((r) => pathname.startsWith(r)) && !token) redirect(...)
 * Reads such path lists so routes outside them are not treated as covered.
 */
function readScope(
  fn: Node,
  info: ModuleInfo,
): { covers: (p: string) => boolean; note: string } | null {
  const include: string[] = [];
  const exclude: string[] = [];

  walk(fn, (node, parent) => {
    if (node.type !== 'CallExpression') return undefined;
    const callee = unwrap(node.callee);
    const name = dottedName(callee) ?? '';
    const segment = lastSegment(name);
    let paths: string[] = [];
    let listName = '';

    if (['startsWith', 'includes', 'some', 'match', 'test'].includes(segment)) {
      paths = node.arguments.flatMap((a) => pathLiterals(a, info));
      if (callee.type === 'MemberExpression') {
        listName = dottedName(callee.object) ?? '';
        paths.push(...pathLiterals(callee.object, info));
      }
    } else if (callee.type === 'Identifier') {
      // isProtectedRoute(req), where isProtectedRoute = createRouteMatcher([...])
      const init = info.variables.get(callee.name);
      if (
        init &&
        unwrap(init).type === 'CallExpression' &&
        lastSegment(dottedName(init) ?? '') === 'createRouteMatcher'
      ) {
        listName = callee.name;
        paths = (unwrap(init) as TSESTree.CallExpression).arguments.flatMap((a) =>
          pathLiterals(a, info),
        );
      }
    }
    paths = paths.filter(
      (p) => !/^\/(?:auth\/)?(?:login|signin|sign-in|signup|sign-up|register)\b/i.test(p),
    );
    if (paths.length === 0) return undefined;

    const negated = parent?.type === 'UnaryExpression' && parent.operator === '!';
    (negated || /public|unprotected|allow|ignored?/i.test(listName) ? exclude : include).push(
      ...paths,
    );
    return undefined;
  });

  const matches = (p: string, pattern: string) => {
    const sample = samplePath(p);
    if (/[(:*]/.test(pattern)) return nextPatternToRegex(pattern).test(sample);
    const base = pattern.replace(/\/$/, '');
    return sample === base || sample.startsWith(`${base}/`);
  };

  if (include.length > 0) {
    return {
      covers: (p) => include.some((pattern) => matches(p, pattern)),
      note: `only protects ${include.map((x) => `\`${x}\``).join(', ')}`,
    };
  }
  if (exclude.length > 0) {
    return {
      covers: (p) => !exclude.some((pattern) => matches(p, pattern)),
      note: `skips auth for ${exclude.map((x) => `\`${x}\``).join(', ')}`,
    };
  }
  return null;
}

/** Path-like string literals in an expression, following module-level array constants. */
function pathLiterals(node: Node, info: ModuleInfo, depth = 0): string[] {
  const n = unwrap(node);
  const value = stringValue(n);
  if (value !== null) return value.startsWith('/') ? [value] : [];
  if (n.type === 'ArrayExpression') {
    return n.elements.flatMap((e) =>
      e && e.type !== 'SpreadElement' ? pathLiterals(e, info, depth) : [],
    );
  }
  if (n.type === 'Identifier' && depth < 2) {
    const init = info.variables.get(n.name);
    return init ? pathLiterals(init, info, depth + 1) : [];
  }
  return [];
}

// ---- paths --------------------------------------------------------------

/** `api/users/[id]/` -> `/api/users/[id]`; `null` for private folders. */
export function appRoutePath(dir: string): string | null {
  const segments = dir.split('/').filter(Boolean);
  if (segments.some((s) => s.startsWith('_'))) return null;
  const kept = segments.filter(
    (s) => !(s.startsWith('(') && s.endsWith(')')) && !s.startsWith('@'),
  );
  return `/${kept.join('/')}`;
}

/** `api/users/index` -> `/api/users`. */
export function pagesRoutePath(route: string): string {
  return `/${route}`.replace(/\/index$/, '') || '/';
}

/** Turns `/api/users/[id]` into a concrete path a matcher can be tested against. */
function samplePath(routePath: string): string {
  return routePath
    .replace(/\[\[\.\.\.[^\]]+\]\]/g, 'x')
    .replace(/\[\.\.\.[^\]]+\]/g, 'x/y')
    .replace(/\[[^\]]+\]/g, 'x');
}

/** Points the finding at `export async function POST` rather than the function body. */
function exportLocation(parsed: ParsedJs, name: string): Node | null {
  for (const stmt of parsed.ast.body) {
    if (stmt.type !== 'ExportNamedDeclaration') continue;
    const decl = stmt.declaration;
    if (decl?.type === 'FunctionDeclaration' && decl.id?.name === name) return stmt;
    if (
      decl?.type === 'VariableDeclaration' &&
      decl.declarations.some((d) => d.id.type === 'Identifier' && d.id.name === name)
    ) {
      return stmt;
    }
    if (stmt.specifiers.some((s) => s.exported.type === 'Identifier' && s.exported.name === name))
      return stmt;
  }
  return null;
}

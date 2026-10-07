import {
  dottedName,
  isFunctionNode,
  lastSegment,
  unwrap,
  walk,
  type Node,
} from '../../parsers/javascript.js';

/**
 * Names of middleware, decorators and functions that perform authentication.
 * Users extend this list with `auth-middleware` in `.leakroute.yml`.
 *
 * Entries with a dot must match the full dotted call (`passport.authenticate`),
 * entries without one match the last segment (`authenticate` also matches
 * `fastify.authenticate`).
 */
export const DEFAULT_AUTH_NAMES: readonly string[] = [
  // Generic / hand-written middleware
  'auth',
  'authenticate',
  'authenticated',
  'authMiddleware',
  'authGuard',
  'authorize',
  'authorized',
  'protect',
  'protectRoute',
  'requireAuth',
  'requireAuthentication',
  'requireLogin',
  'requireUser',
  'requireSession',
  'requireAdmin',
  'requireRole',
  'requireRoles',
  'requirePermission',
  'requirePermissions',
  'requireScope',
  'isAuthenticated',
  'isLoggedIn',
  'isAdmin',
  'ensureAuthenticated',
  'ensureLoggedIn',
  'checkAuth',
  'checkJwt',
  'verifyToken',
  'verifyJwt',
  'verifyJWT',
  'verifyAccessToken',
  'verifySession',
  'verifyApiKey',
  'validateToken',
  'validateSession',
  'validateRequest',
  'jwtVerify',
  // Libraries
  'passport.authenticate',
  'jwt',
  'expressjwt',
  'expressJwt',
  'jwt.verify',
  'basicAuth',
  'ClerkExpressRequireAuth',
  'getAuth',
  'currentUser',
  'getServerSession',
  'getSession',
  'getToken',
  'getIronSession',
  'getKindeServerSession',
  'withAuth',
  'withApiAuthRequired',
  'withPageAuthRequired',
  'auth.getUser',
  'auth.getClaims',
  'auth.protect',
  'verifyIdToken',
  'verifySessionCookie',
  // Python (Flask / FastAPI / Django)
  'login_required',
  'jwt_required',
  'auth_required',
  'token_required',
  'permission_required',
  'permission_classes',
  'roles_required',
  'roles_accepted',
  'admin_required',
  'fresh_login_required',
  'get_current_user',
  'get_current_active_user',
  'require_auth',
  'require_user',
  'require_admin',
  'verify_token',
  'verify_jwt_in_request',
  'HTTPBearer',
  'HTTPBasic',
  'OAuth2PasswordBearer',
  'APIKeyHeader',
  'APIKeyCookie',
  'Security',
];

/**
 * Catches common hand-written names that aren't in the list, e.g. `ensureUser`,
 * `requireApiKey`, `jwtGuard`. Deliberately anchored so `checkUserExists` or
 * `sessionMiddleware` (express-session, not auth) don't count.
 */
const AUTH_NAME_HEURISTIC =
  /^(?:require|ensure|check|verify|validate|is|must|assert)_?(?:auth|authenticated|authorized|logged_?in|login|user|session|token|jwt|admin|role|roles|permission|permissions|scope|scopes|api_?key|bearer)(?:_?middleware)?$|^(?:auth|jwt|token|session|bearer|api_?key)_?(?:guard|required|check|verify|verifier|middleware|handler|hook)$|guard$/i;

/**
 * `auth.required`, `jwtMiddleware.verify`, `session.ensure`: a generic verb on an
 * object whose name says auth. Common in hand-rolled auth modules.
 */
const AUTH_OBJECT = /auth|jwt|session|passport|token|guard/i;
const AUTH_VERB =
  /^(?:required?|protect(?:ed)?|ensure|verify|check|guard|authenticated?|authorized?|loggedIn|isLoggedIn|user)$/i;

export type AuthMatcher = (name: string) => boolean;

export function createAuthMatcher(extra: readonly string[]): AuthMatcher {
  const dotted = new Set<string>();
  const plain = new Set<string>();
  for (const name of [...DEFAULT_AUTH_NAMES, ...extra]) {
    (name.includes('.') ? dotted : plain).add(name);
  }
  return (name) => {
    if (dotted.has(name) || plain.has(lastSegment(name))) return true;
    for (const entry of dotted) if (name.endsWith(`.${entry}`)) return true;
    const segments = name.split('.');
    if (
      segments.length > 1 &&
      AUTH_VERB.test(segments.at(-1) ?? '') &&
      segments.slice(0, -1).some((s) => AUTH_OBJECT.test(s))
    ) {
      return true;
    }
    return AUTH_NAME_HEURISTIC.test(lastSegment(name));
  };
}

const UNAUTHORIZED_NAMES =
  /^(?:Unauthorized|Forbidden|Unauthenticated|NotAuthenticated|AuthenticationError|AuthorizationError|PermissionDenied)\w*$|^(?:UNAUTHORIZED|FORBIDDEN|HTTP_401_UNAUTHORIZED|HTTP_403_FORBIDDEN)$/;

/**
 * Looks for evidence that a function body authenticates the request itself:
 * a call to a known auth function, or responding 401/403.
 * Returns the evidence (for the finding's explanation) or `null`.
 */
export function findAuthEvidence(fn: Node, isAuth: AuthMatcher): string | null {
  let evidence: string | null = null;
  walk(fn, (node) => {
    if (evidence) return false;
    // Nested functions that are defined but maybe never called still count:
    // inline helpers like `const user = await getUser()` are the common case.
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const name = dottedName(node.callee);
      if (name && isAuth(name)) evidence = `calls \`${name}()\``;
      else if (name && UNAUTHORIZED_NAMES.test(lastSegment(name))) evidence = `throws \`${name}\``;
    } else if (node.type === 'Literal' && (node.value === 401 || node.value === 403)) {
      evidence = `responds with ${String(node.value)}`;
    } else if (node.type === 'MemberExpression' || node.type === 'Identifier') {
      const name = dottedName(node);
      if (name && UNAUTHORIZED_NAMES.test(lastSegment(name))) evidence = `uses \`${name}\``;
    }
    return undefined;
  });
  return evidence;
}

/** If `node` is a function (possibly wrapped), returns it. */
export function asFunction(node: Node | null | undefined): Node | null {
  if (!node) return null;
  const n = unwrap(node);
  return isFunctionNode(n) ? n : null;
}

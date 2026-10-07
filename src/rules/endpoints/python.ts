import path from 'node:path';
import { fingerprint } from '../../core/fingerprint.js';
import { assessEndpointRisk, type HttpMethod } from '../../core/risk.js';
import type { Finding, Severity } from '../../core/types.js';
import { lastSegment } from '../../parsers/javascript.js';
import {
  pyArgs,
  pyDotted,
  pyPosition,
  pyString,
  walkPy,
  type ParsedPy,
  type PyNode,
} from '../../parsers/python.js';
import { fastapiRouteFromDecorator, FASTAPI_CONSTRUCTORS } from './fastapi.js';
import { flaskRouteFromDecorator, FLASK_CONSTRUCTORS } from './flask.js';
import type { EndpointContext } from './types.js';

/**
 * FastAPI and Flask route analysis.
 *
 * Like the Express analyzer, this builds a graph of apps/routers/blueprints,
 * links `include_router` / `register_blueprint` across modules, and walks each
 * chain collecting the auth that applies: FastAPI `dependencies=[...]` on the
 * app, router, include or route, auth parameters (`Depends`/`Security`), Flask
 * decorators and `before_request` hooks, and checks inside the handler body.
 */

export type PyFramework = 'fastapi' | 'flask';

export interface PyRoute {
  methods: HttpMethod[];
  path: string;
  line: number;
  column: number;
  /** Auth found on the route itself (decorator, dependency, parameter or body). */
  protectedBy: string | null;
  /** Flask: an auth decorator placed above the route decorator, which never runs. */
  misplacedDecorator?: string;
}

interface PyRouter {
  id: string;
  file: string;
  label: string;
  framework: PyFramework;
  isApp: boolean;
  ownPrefix: string;
  guards: string[];
  routes: PyRoute[];
  includes: PyInclude[];
}

interface PyInclude {
  target: PyRef;
  /** `null` when the include didn't pass a prefix. */
  prefix: string | null;
  guards: string[];
  label: string;
}

type PyRef = { kind: 'router'; id: string } | { kind: 'symbol'; file: string; name: string };

type PyBinding =
  | { kind: 'module'; file: string }
  | { kind: 'symbol'; file: string; name: string }
  | { kind: 'external'; module: string; name: string }
  | { kind: 'router'; id: string }
  | { kind: 'function'; node: PyNode }
  | { kind: 'value'; node: PyNode };

interface PyModule {
  file: string;
  parsed: ParsedPy;
  bindings: Map<string, PyBinding>;
  usesFramework: boolean;
}

type Scope = Map<string, PyBinding>;

const FRAMEWORK_MODULE = /^(?:fastapi|flask|starlette|flask_\w+|quart)(?:\.|$)/;

const UNAUTHORIZED =
  /^(?:HTTP_401_UNAUTHORIZED|HTTP_403_FORBIDDEN|Unauthorized|Forbidden|PermissionDenied|NotAuthenticated|AuthenticationFailed)$/;

const MAX_DEPTH = 3;

export class PythonAnalyzer {
  private readonly modules = new Map<string, PyModule>();
  private readonly routers = new Map<string, PyRouter>();
  private readonly pendingRoutes: { ref: PyRef; route: PyRoute }[] = [];
  private readonly pendingIncludes: { parent: PyRef; include: PyInclude }[] = [];
  private readonly pendingGuards: { ref: PyRef; label: string }[] = [];
  private readonly paths: string[];

  constructor(
    files: readonly ParsedPy[],
    private readonly ctx: EndpointContext,
  ) {
    this.paths = files.map((f) => f.file.path);
    for (const parsed of files) this.modules.set(parsed.file.path, this.collectBindings(parsed));
    for (const mod of this.modules.values()) {
      this.visitBlock(mod, mod.parsed.root, [mod.bindings]);
    }
  }

  // ---- pass 1: module-level names ---------------------------------------

  private collectBindings(parsed: ParsedPy): PyModule {
    const file = parsed.file.path;
    const mod: PyModule = { file, parsed, bindings: new Map(), usesFramework: false };

    for (const stmt of parsed.root.namedChildren) {
      if (stmt.type === 'import_from_statement') this.bindFromImport(mod, stmt);
      else if (stmt.type === 'import_statement') this.bindImport(mod, stmt);
    }
    this.bindBlock(mod, parsed.root, mod.bindings, '');
    return mod;
  }

  /** Declares functions, assignments and routers of one block into `scope`. */
  private bindBlock(mod: PyModule, block: PyNode, scope: Scope, scopeKey: string): void {
    for (const stmt of block.namedChildren) {
      const def =
        stmt.type === 'decorated_definition' ? stmt.childForFieldName('definition') : stmt;
      if (def?.type === 'function_definition') {
        const name = def.childForFieldName('name')?.text;
        if (name) scope.set(name, { kind: 'function', node: def });
        continue;
      }
      if (stmt.type !== 'expression_statement') continue;
      const assignment = stmt.namedChildren[0];
      if (assignment?.type !== 'assignment') continue;
      const left = assignment.childForFieldName('left');
      const right = assignment.childForFieldName('right');
      if (left?.type !== 'identifier' || !right) continue;

      const router =
        right.type === 'call' ? this.routerFromConstructor(mod, right, left.text, scopeKey) : null;
      scope.set(
        left.text,
        router ? { kind: 'router', id: router.id } : { kind: 'value', node: right },
      );
    }
  }

  private bindFromImport(mod: PyModule, stmt: PyNode): void {
    const moduleNode = stmt.childForFieldName('module_name');
    if (!moduleNode) return;
    let level = 0;
    let moduleName = moduleNode.text;
    if (moduleNode.type === 'relative_import') {
      const prefix = moduleNode.namedChildren.find((c) => c.type === 'import_prefix')?.text ?? '';
      level = prefix.length;
      moduleName = moduleNode.namedChildren.find((c) => c.type === 'dotted_name')?.text ?? '';
    }
    if (level === 0 && FRAMEWORK_MODULE.test(moduleName)) mod.usesFramework = true;

    for (const nameNode of stmt.childrenForFieldName('name')) {
      const imported =
        nameNode.type === 'aliased_import'
          ? nameNode.childForFieldName('name')?.text
          : nameNode.text;
      const local =
        nameNode.type === 'aliased_import' ? nameNode.childForFieldName('alias')?.text : imported;
      if (!imported || !local) continue;

      // `from app.routers import users` may name a submodule or a symbol.
      const submodule = this.resolveModule(
        mod.file,
        moduleName ? `${moduleName}.${imported}` : imported,
        level,
      );
      if (submodule) {
        mod.bindings.set(local, { kind: 'module', file: submodule });
        continue;
      }
      const target = this.resolveModule(mod.file, moduleName, level);
      mod.bindings.set(
        local,
        target
          ? { kind: 'symbol', file: target, name: imported }
          : { kind: 'external', module: moduleName, name: imported },
      );
    }
  }

  private bindImport(mod: PyModule, stmt: PyNode): void {
    for (const nameNode of stmt.childrenForFieldName('name')) {
      const moduleName =
        nameNode.type === 'aliased_import'
          ? nameNode.childForFieldName('name')?.text
          : nameNode.text;
      if (!moduleName) continue;
      if (FRAMEWORK_MODULE.test(moduleName)) mod.usesFramework = true;
      if (nameNode.type !== 'aliased_import') continue;
      const alias = nameNode.childForFieldName('alias')?.text;
      const target = this.resolveModule(mod.file, moduleName, 0);
      if (alias && target) mod.bindings.set(alias, { kind: 'module', file: target });
    }
  }

  /** Resolves `a.b.c` (absolute) or `.b` (relative, `level` dots) to a scanned file. */
  private resolveModule(fromFile: string, moduleName: string, level: number): string | null {
    const rel = moduleName.replace(/\./g, '/');
    if (level > 0) {
      let base = path.posix.dirname(fromFile);
      for (let i = 1; i < level; i++) base = path.posix.dirname(base);
      const stem = rel ? (base === '.' ? rel : `${base}/${rel}`) : base;
      return [`${stem}.py`, `${stem}/__init__.py`].find((c) => this.paths.includes(c)) ?? null;
    }
    if (!rel) return null;
    const matches = this.paths.filter(
      (p) =>
        p === `${rel}.py` ||
        p === `${rel}/__init__.py` ||
        p.endsWith(`/${rel}.py`) ||
        p.endsWith(`/${rel}/__init__.py`),
    );
    return matches.sort((a, b) => a.length - b.length)[0] ?? null;
  }

  private routerFromConstructor(
    mod: PyModule,
    call: PyNode,
    label: string,
    scopeKey: string,
  ): PyRouter | null {
    const ctor = lastSegment(pyDotted(call) ?? '');
    const framework: PyFramework | null = FASTAPI_CONSTRUCTORS.has(ctor)
      ? 'fastapi'
      : FLASK_CONSTRUCTORS.has(ctor)
        ? 'flask'
        : null;
    if (!framework || !mod.usesFramework) return null;

    const args = pyArgs(call);
    const id = `${mod.file}#${scopeKey}${label}@${call.startIndex}`;
    const router: PyRouter = {
      id,
      file: mod.file,
      label,
      framework,
      isApp: ctor === 'FastAPI' || ctor === 'Flask' || ctor === 'Quart',
      ownPrefix: pyString(args.keywords.get(framework === 'flask' ? 'url_prefix' : 'prefix')) ?? '',
      guards: [],
      routes: [],
      includes: [],
    };
    const deps = args.keywords.get('dependencies');
    if (deps) router.guards.push(...this.dependencyGuards(mod, deps, [mod.bindings]));
    this.routers.set(id, router);
    return router;
  }

  // ---- pass 2: routes, includes, hooks ---------------------------------

  private visitBlock(mod: PyModule, block: PyNode, scopes: Scope[]): void {
    for (const stmt of block.namedChildren) {
      if (stmt.type === 'decorated_definition') {
        this.handleDecorated(mod, stmt, scopes);
        const def = stmt.childForFieldName('definition');
        if (def?.type === 'function_definition') this.visitFunction(mod, def, scopes);
      } else if (stmt.type === 'function_definition') {
        this.visitFunction(mod, stmt, scopes);
      } else if (stmt.type === 'expression_statement') {
        const call = stmt.namedChildren[0];
        if (call?.type === 'call') this.handleCall(mod, call, scopes);
      } else if (
        [
          'if_statement',
          'with_statement',
          'try_statement',
          'block',
          'else_clause',
          'elif_clause',
        ].includes(stmt.type)
      ) {
        this.visitBlock(mod, stmt, scopes);
      }
    }
  }

  /** App factories: `def create_app(): app = Flask(__name__); ...`. */
  private visitFunction(mod: PyModule, fn: PyNode, scopes: Scope[]): void {
    const body = fn.childForFieldName('body');
    if (!body) return;
    const local: Scope = new Map();
    this.bindBlock(mod, body, local, `${fn.childForFieldName('name')?.text ?? 'fn'}.`);
    this.visitBlock(mod, body, [local, ...scopes]);
  }

  private lookup(name: string, scopes: Scope[]): PyBinding | undefined {
    for (const scope of scopes) {
      const b = scope.get(name);
      if (b) return b;
    }
    return undefined;
  }

  /** A router reference: `router`, `users.router`, an imported `app`. */
  private routerRef(mod: PyModule, node: PyNode | null | undefined, scopes: Scope[]): PyRef | null {
    if (!node) return null;
    if (node.type === 'identifier') {
      const b = this.lookup(node.text, scopes);
      if (b?.kind === 'router') return { kind: 'router', id: b.id };
      if (b?.kind === 'symbol') return { kind: 'symbol', file: b.file, name: b.name };
      return null;
    }
    if (node.type === 'attribute') {
      const object = node.childForFieldName('object');
      const attr = node.childForFieldName('attribute')?.text;
      if (object?.type === 'identifier' && attr) {
        const b = this.lookup(object.text, scopes);
        if (b?.kind === 'module') return { kind: 'symbol', file: b.file, name: attr };
      }
    }
    return null;
  }

  private handleDecorated(mod: PyModule, stmt: PyNode, scopes: Scope[]): void {
    const def = stmt.childForFieldName('definition');
    if (def?.type !== 'function_definition') return;
    const decorators = stmt.namedChildren
      .filter((c) => c.type === 'decorator')
      .map((d) => d.namedChildren[0]);

    decorators.forEach((expr, index) => {
      if (!expr) return;
      // @app.get(...) / @bp.route(...): a call on an attribute of a router.
      const callee = expr.type === 'call' ? expr.childForFieldName('function') : expr;
      if (callee?.type !== 'attribute') return;
      const ref = this.routerRef(mod, callee.childForFieldName('object'), scopes);
      if (!ref) return;
      const method = callee.childForFieldName('attribute')?.text ?? '';

      if (method === 'before_request' || method === 'before_app_request') {
        const evidence = this.functionEvidence(mod, def, 0);
        if (evidence)
          this.pendingGuards.push({
            ref,
            label: `\`before_request\` hook \`${def.childForFieldName('name')?.text}\` that ${evidence}`,
          });
        return;
      }
      if (expr.type !== 'call') return;

      const framework = this.frameworkOf(ref);
      const route =
        framework === 'flask'
          ? flaskRouteFromDecorator(method, expr)
          : (fastapiRouteFromDecorator(method, expr) ?? flaskRouteFromDecorator(method, expr));
      if (!route) return;

      const pyRoute: PyRoute = { ...route, ...pyPosition(expr.parent ?? expr), protectedBy: null };
      pyRoute.protectedBy = this.routeProtection(
        mod,
        def,
        decorators,
        index,
        expr,
        scopes,
        pyRoute,
      );
      this.pendingRoutes.push({ ref, route: pyRoute });
    });
  }

  private frameworkOf(ref: PyRef): PyFramework | null {
    const id = this.resolve(ref);
    return id ? (this.routers.get(id)?.framework ?? null) : null;
  }

  /** Auth that applies to one route, from its decorators, dependencies, parameters and body. */
  private routeProtection(
    mod: PyModule,
    def: PyNode,
    decorators: (PyNode | null | undefined)[],
    routeIndex: number,
    routeDecorator: PyNode,
    scopes: Scope[],
    route: PyRoute,
  ): string | null {
    // Route-level dependencies=[Depends(...)]
    const deps = pyArgs(routeDecorator).keywords.get('dependencies');
    const depGuards = deps ? this.dependencyGuards(mod, deps, scopes) : [];
    if (depGuards[0]) return depGuards[0];

    // Other decorators. Python applies them bottom-up, so for Flask only the ones
    // *below* the route decorator wrap the registered view.
    for (const [index, expr] of decorators.entries()) {
      if (!expr || index === routeIndex) continue;
      const label = this.decoratorAuth(mod, expr, scopes);
      if (!label) continue;
      if (index > routeIndex) return label;
      route.misplacedDecorator ??= pyDotted(expr) ?? expr.text;
    }

    // Parameters: user = Depends(get_current_user), token: Annotated[str, Depends(oauth2_scheme)]
    const params = def.childForFieldName('parameters');
    for (const param of params?.namedChildren ?? []) {
      for (const field of ['type', 'value']) {
        const node = param.childForFieldName(field);
        const label = node ? this.dependencyLabel(mod, node, scopes, 0) : null;
        if (label) return label;
      }
    }

    const evidence = this.functionEvidence(mod, def, 0);
    return evidence ? `the handler ${evidence}` : null;
  }

  private decoratorAuth(mod: PyModule, expr: PyNode, scopes: Scope[]): string | null {
    const name = pyDotted(expr);
    if (name && this.ctx.isAuth(name)) return `\`@${name}\``;
    const fn = expr.type === 'call' ? expr.childForFieldName('function') : expr;
    const resolved = fn ? this.resolveFunction(mod, fn, scopes) : null;
    const evidence = resolved ? this.functionEvidence(resolved.mod, resolved.node, 1) : null;
    return evidence ? `\`@${name}\` (${evidence})` : null;
  }

  private handleCall(mod: PyModule, call: PyNode, scopes: Scope[]): void {
    const callee = call.childForFieldName('function');
    if (callee?.type !== 'attribute') return;
    const method = callee.childForFieldName('attribute')?.text ?? '';
    const parent = this.routerRef(mod, callee.childForFieldName('object'), scopes);
    if (!parent) return;
    const args = pyArgs(call);

    if (method === 'include_router' || method === 'register_blueprint') {
      const target = this.routerRef(mod, args.positional[0], scopes);
      if (!target) return;
      const prefix = pyString(
        args.keywords.get(method === 'include_router' ? 'prefix' : 'url_prefix'),
      );
      const deps = args.keywords.get('dependencies');
      this.pendingIncludes.push({
        parent,
        include: {
          target,
          prefix,
          guards: deps ? this.dependencyGuards(mod, deps, scopes) : [],
          label: args.positional[0]?.text ?? 'router',
        },
      });
    } else if (method === 'mount') {
      const target = this.routerRef(mod, args.positional[1] ?? args.keywords.get('app'), scopes);
      const prefix = pyString(args.positional[0] ?? args.keywords.get('path'));
      if (target) {
        this.pendingIncludes.push({
          parent,
          include: { target, prefix, guards: [], label: args.positional[1]?.text ?? 'app' },
        });
      }
    } else if (method === 'before_request') {
      const target = args.positional[0];
      const resolved = target ? this.resolveFunction(mod, target, scopes) : null;
      const evidence = resolved ? this.functionEvidence(resolved.mod, resolved.node, 0) : null;
      if (evidence)
        this.pendingGuards.push({
          ref: parent,
          label: `\`before_request\` hook \`${target?.text}\` that ${evidence}`,
        });
    }
  }

  // ---- auth evidence -----------------------------------------------------

  /** Labels for each auth dependency in `dependencies=[Depends(a), Depends(b)]`. */
  private dependencyGuards(mod: PyModule, list: PyNode, scopes: Scope[]): string[] {
    const items = list.type === 'list' || list.type === 'tuple' ? list.namedChildren : [list];
    return items
      .map((item) => this.dependencyLabel(mod, item, scopes, 0))
      .filter((l): l is string => l !== null);
  }

  /**
   * Does this expression bring in authentication? Handles `Depends(get_current_user)`,
   * `Security(...)`, auth schemes (`OAuth2PasswordBearer`), and aliases such as
   * `CurrentUser = Annotated[User, Depends(get_current_user)]`.
   */
  private dependencyLabel(
    mod: PyModule,
    expr: PyNode,
    scopes: Scope[],
    depth: number,
  ): string | null {
    if (depth > MAX_DEPTH) return null;
    let label: string | null = null;
    walkPy(expr, (node) => {
      if (label) return false;
      if (node.type === 'call') {
        const name = pyDotted(node) ?? '';
        const segment = lastSegment(name);
        if (segment === 'Depends' || segment === 'Security') {
          const args = pyArgs(node);
          const target = args.positional[0] ?? args.keywords.get('dependency');
          const inner = target ? this.dependencyTarget(mod, target, scopes, depth) : null;
          if (inner)
            label = `\`${segment}(${target?.text})\`${inner === true ? '' : ` (${inner})`}`;
          else if (segment === 'Security') label = `\`Security(${target?.text ?? ''})\``;
          return false;
        }
        if (name && this.ctx.isAuth(name)) {
          label = `\`${name}\``;
          return false;
        }
      } else if (node.type === 'identifier') {
        // Annotated aliases and scheme instances defined elsewhere in the module.
        const b = this.lookup(node.text, scopes);
        if (b?.kind === 'value') label = this.dependencyLabel(mod, b.node, scopes, depth + 1);
      }
      return undefined;
    });
    return label;
  }

  /** `true`/evidence string when a `Depends(...)` target authenticates. */
  private dependencyTarget(
    mod: PyModule,
    target: PyNode,
    scopes: Scope[],
    depth: number,
  ): string | true | null {
    const name = pyDotted(target);
    if (name && this.ctx.isAuth(name)) return true;
    const fnNode = target.type === 'call' ? target.childForFieldName('function') : target;
    const resolved = fnNode ? this.resolveFunction(mod, fnNode, scopes) : null;
    if (resolved) return this.functionEvidence(resolved.mod, resolved.node, depth + 1);
    if (target.type === 'identifier') {
      const b = this.lookup(target.text, scopes);
      if (b?.kind === 'value' && this.dependencyLabel(mod, b.node, scopes, depth + 1)) return true;
    }
    return null;
  }

  private resolveFunction(
    mod: PyModule,
    node: PyNode,
    scopes: Scope[],
    depth = 0,
  ): { mod: PyModule; node: PyNode } | null {
    if (depth > 5) return null;
    if (node.type === 'identifier') {
      const b = this.lookup(node.text, scopes);
      if (b?.kind === 'function') return { mod, node: b.node };
      if (b?.kind === 'symbol') return this.resolveSymbolFunction(b.file, b.name, depth + 1);
    } else if (node.type === 'attribute') {
      const object = node.childForFieldName('object');
      const attr = node.childForFieldName('attribute')?.text;
      const b = object?.type === 'identifier' ? this.lookup(object.text, scopes) : undefined;
      if (b?.kind === 'module' && attr) return this.resolveSymbolFunction(b.file, attr, depth + 1);
    }
    return null;
  }

  private resolveSymbolFunction(
    file: string,
    name: string,
    depth: number,
  ): { mod: PyModule; node: PyNode } | null {
    const target = this.modules.get(file);
    const b = target?.bindings.get(name);
    if (!target || !b) return null;
    if (b.kind === 'function') return { mod: target, node: b.node };
    if (b.kind === 'symbol')
      return depth > 5 ? null : this.resolveSymbolFunction(b.file, b.name, depth + 1);
    return null;
  }

  /** Evidence that a function body authenticates the request. */
  private functionEvidence(mod: PyModule, fn: PyNode, depth: number): string | null {
    let evidence: string | null = null;
    const body = fn.childForFieldName('body') ?? fn;
    walkPy(body, (node) => {
      if (evidence) return false;
      switch (node.type) {
        case 'call': {
          const name = pyDotted(node) ?? '';
          if (this.ctx.isAuth(name)) evidence = `calls \`${name}()\``;
          else if (/(?:^|\.)jwt\.decode$/.test(name)) evidence = `decodes a JWT with \`${name}()\``;
          else if (lastSegment(name) === 'url_for' && /login|signin/i.test(node.text))
            evidence = 'redirects to the login page';
          else if (depth < 2) {
            const fnNode = node.childForFieldName('function');
            const helper = fnNode ? this.resolveFunction(mod, fnNode, [mod.bindings]) : null;
            if (helper && helper.node.startIndex !== fn.startIndex) {
              const inner = this.functionEvidence(helper.mod, helper.node, depth + 1);
              if (inner) evidence = `calls \`${name}()\`, which ${inner}`;
            }
          }
          break;
        }
        case 'integer':
          if (node.text === '401' || node.text === '403') evidence = `responds with ${node.text}`;
          break;
        case 'identifier':
          if (UNAUTHORIZED.test(node.text)) evidence = `uses \`${node.text}\``;
          break;
        case 'attribute': {
          const attr = node.childForFieldName('attribute')?.text ?? '';
          if (attr === 'is_authenticated' || attr === 'is_anonymous')
            evidence = `checks \`${node.text}\``;
          else if (UNAUTHORIZED.test(attr)) evidence = `uses \`${node.text}\``;
          break;
        }
      }
      return undefined;
    });
    return evidence;
  }

  // ---- linking & findings -----------------------------------------------

  private resolve(ref: PyRef, depth = 0): string | null {
    if (ref.kind === 'router') return ref.id;
    if (depth > 5) return null;
    const b = this.modules.get(ref.file)?.bindings.get(ref.name);
    if (b?.kind === 'router') return b.id;
    if (b?.kind === 'symbol')
      return this.resolve({ kind: 'symbol', file: b.file, name: b.name }, depth + 1);
    return null;
  }

  findings(): Finding[] {
    for (const { ref, route } of this.pendingRoutes) {
      const id = this.resolve(ref);
      if (id) this.routers.get(id)?.routes.push(route);
    }
    for (const { ref, label } of this.pendingGuards) {
      const id = this.resolve(ref);
      if (id) this.routers.get(id)?.guards.push(label);
    }
    const children = new Map<string, { include: PyInclude; child: PyRouter }[]>();
    const hasParent = new Set<string>();
    for (const { parent, include } of this.pendingIncludes) {
      const parentId = this.resolve(parent);
      const childId = this.resolve(include.target);
      const child = childId ? this.routers.get(childId) : undefined;
      if (!parentId || !child || parentId === child.id) continue;
      hasParent.add(child.id);
      children.set(parentId, [...(children.get(parentId) ?? []), { include, child }]);
    }

    const out = new Map<string, Finding>();
    const visit = (
      node: PyRouter,
      prefix: string,
      guards: string[],
      chain: string[],
      mounted: boolean,
      stack: Set<string>,
    ) => {
      if (stack.has(node.id)) return;
      stack.add(node.id);
      const allGuards = [...guards, ...node.guards];

      for (const route of node.routes) {
        if (allGuards.length > 0 || route.protectedBy) continue;
        const fullPath = joinPy(prefix, route.path);
        if (this.ctx.isPublic(fullPath)) continue;
        const finding = this.toFinding(node, route, fullPath, chain, mounted);
        if (!out.has(finding.fingerprint)) out.set(finding.fingerprint, finding);
      }

      for (const { include, child } of children.get(node.id) ?? []) {
        // Flask's url_prefix on register_blueprint replaces the blueprint's own;
        // FastAPI's include_router prefix is prepended to the router's.
        const childPrefix =
          child.framework === 'flask'
            ? joinPy(prefix, include.prefix ?? child.ownPrefix)
            : joinPy(joinPy(prefix, include.prefix ?? ''), child.ownPrefix);
        const where =
          child.file === node.file ? include.label : `${include.label} in ${child.file}`;
        visit(
          child,
          childPrefix,
          [...allGuards, ...include.guards],
          [...chain, where],
          true,
          stack,
        );
      }
      stack.delete(node.id);
    };

    for (const node of this.routers.values()) {
      if (hasParent.has(node.id)) continue;
      visit(node, node.ownPrefix, [], [node.label], node.isApp, new Set());
    }
    return [...out.values()];
  }

  private toFinding(
    node: PyRouter,
    route: PyRoute,
    fullPath: string,
    chain: string[],
    mounted: boolean,
  ): Finding {
    const method =
      route.methods.find((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m)) ??
      route.methods[0] ??
      'GET';
    const methods = route.methods.join(', ');
    const risk = assessEndpointRisk(method, fullPath);
    const chainText = chain.map((c) => `\`${c}\``).join(' → ');

    let ruleId = `endpoint/${node.framework}-unprotected-route`;
    let severity: Severity = risk.severity;
    let reason: string;
    let remediation: string;

    if (route.misplacedDecorator) {
      ruleId = 'endpoint/flask-auth-decorator-order';
      severity = 'high';
      reason = `\`@${route.misplacedDecorator}\` is placed above the route decorator. Python applies decorators bottom-up, so Flask registers the undecorated function and the auth check never runs for \`${methods} ${fullPath}\`.`;
      remediation = `Move \`@${route.misplacedDecorator}\` directly below the \`@...route(...)\` decorator.`;
    } else if (node.framework === 'fastapi') {
      reason = `No authentication found for \`${methods} ${fullPath}\`: no auth dependency on the route, its parameters or the router chain ${chainText}, and the handler does not raise 401/403 or call a known auth function. ${risk.why}`;
      remediation =
        'Add an auth dependency to the route (`current_user: User = Depends(get_current_user)`) or to the router (`APIRouter(dependencies=[Depends(get_current_user)])` / `include_router(..., dependencies=[...])`). If the route is meant to be public, add it to `public-routes` in .leakroute.yml; if your dependency has a custom name, add it to `auth-middleware`.';
    } else {
      reason = `No authentication found for \`${methods} ${fullPath}\`: no auth decorator below the route decorator, no \`before_request\` hook that checks auth on ${chainText}, and the view does not check \`current_user\` or abort with 401/403. ${risk.why}`;
      remediation =
        'Add `@login_required` (or your auth decorator) directly below `@app.route(...)`, or protect the whole blueprint with a `@bp.before_request` hook that checks authentication. If the route is meant to be public, add it to `public-routes` in .leakroute.yml; if your decorator has a custom name, add it to `auth-middleware`.';
    }
    if (!mounted && !route.misplacedDecorator) {
      reason += ` \`${node.label}\` is not included in any app leakroute could find, so dependencies added there are not visible.`;
    }

    return {
      ruleId,
      category: 'endpoint',
      severity,
      file: node.file,
      line: route.line,
      column: route.column,
      title: `Possible unprotected endpoint: ${methods} ${fullPath}`,
      reason,
      remediation,
      fingerprint: fingerprint(ruleId, node.file, methods, fullPath),
    };
  }
}

function joinPy(prefix: string, sub: string): string {
  const joined = `/${prefix}/${sub}`.replace(/\/{2,}/g, '/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : joined;
}

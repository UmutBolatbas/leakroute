import { fingerprint } from '../../core/fingerprint.js';
import { assessEndpointRisk, type HttpMethod } from '../../core/risk.js';
import type { Finding } from '../../core/types.js';
import {
  children,
  dottedName,
  isFunctionNode,
  lastSegment,
  position,
  stringValue,
  unwrap,
  type FunctionNode,
  type Node,
  type ParsedJs,
  type TSESTree,
} from '../../parsers/javascript.js';
import { deepAuthEvidence, resolveImportedFunction } from './evidence.js';
import { fastifyOptionGuards, FASTIFY_AUTH_HOOKS } from './fastify.js';
import { requireSource, resolveModule, type ImportRef, type ModuleInfo } from './modules.js';
import type { EndpointContext, JsProject } from './types.js';

/**
 * Express and Fastify route analysis.
 *
 * Pass 1 (per file) builds a graph of routers: their routes, middleware (`use`),
 * hooks (`addHook`) and mounts (`use('/x', router)`, `register(plugin)`,
 * `setupRoutes(app)`), keeping source order because Express middleware only
 * applies to routes registered after it.
 *
 * Pass 2 links mounts across files through imports and walks every router chain
 * from the app down, collecting the auth guards that apply to each route.
 */

type Framework = 'express' | 'fastify';

const ROUTE_METHODS: Record<string, HttpMethod> = {
  get: 'GET',
  post: 'POST',
  put: 'PUT',
  patch: 'PATCH',
  delete: 'DELETE',
  del: 'DELETE',
  head: 'HEAD',
  options: 'OPTIONS',
  all: 'ALL',
};

const RECEIVER_NAMES = /^(?:app|router|server|api|fastify)$/i;

/** A reference to a router that may live in another file. */
type Ref =
  { kind: 'id'; id: string } | { kind: 'import'; file: string; ref: ImportRef; param: number };

/** Something that authenticates requests, or an import that might (resolved in pass 2). */
export type Guard =
  | { kind: 'known'; label: string }
  | { kind: 'pending'; label: string; file: string; ref: ImportRef };

interface HandlerInfo {
  label: string;
  evidence: string | null;
  /** Handler imported from another file; inspected in pass 2. */
  pending?: { file: string; ref: ImportRef };
  /** Defined somewhere leakroute can't follow (e.g. `controller.create`). */
  opaque: boolean;
}

interface RouteDef {
  method: HttpMethod;
  path: string;
  order: number;
  line: number;
  column: number;
  guards: Guard[];
  handler: HandlerInfo;
}

interface UseDef {
  order: number;
  prefix: string;
  guards: Guard[];
}

interface MountDef {
  order: number;
  prefix: string;
  guards: Guard[];
  target: Ref;
  /** For `app.use(importedThing)`: if it turns out not to be a router, it is middleware. */
  fallback?: Guard;
  /** How the mount site refers to the child, e.g. `adminRouter`. */
  label?: string;
}

interface RouterNode {
  id: string;
  file: string;
  label: string;
  framework: Framework;
  /** Created by `express()` / `fastify()`, i.e. the root of a chain. */
  isApp: boolean;
  /** We are confident this is a server router and not, say, an axios instance. */
  gated: boolean;
  /** For `import app from './app'; app.get(...)`: the imported router. */
  aliasOf?: Ref;
  routes: RouteDef[];
  uses: UseDef[];
  mounts: MountDef[];
  /** Fastify hooks apply to every route in the instance regardless of order. */
  hooks: Guard[];
}

type Binding =
  | { kind: 'router'; id: string }
  | { kind: 'param'; fn: FunctionNode; index: number; name: string }
  | { kind: 'import'; ref: ImportRef }
  | { kind: 'function'; node: FunctionNode }
  | { kind: 'other' };

class Scope {
  readonly vars = new Map<string, Binding>();
  constructor(readonly parent: Scope | null) {}
  lookup(name: string): Binding | undefined {
    return this.vars.get(name) ?? this.parent?.lookup(name);
  }
}

class FileCollector {
  readonly file: string;
  readonly framework: Framework | null;
  readonly moduleScope = new Scope(null);

  constructor(
    readonly parsed: ParsedJs,
    readonly info: ModuleInfo,
    readonly routers: Map<string, RouterNode>,
    readonly ctx: EndpointContext,
    readonly project: JsProject,
  ) {
    this.file = parsed.file.path;
    const sources = [...info.imports.values()].map((i) => i.source);
    this.framework = sources.some(
      (s) => s === 'fastify' || s.startsWith('@fastify/') || s === 'fastify-plugin',
    )
      ? 'fastify'
      : sources.some((s) => s === 'express' || s.startsWith('express-'))
        ? 'express'
        : null;
  }

  run(): void {
    for (const [local, ref] of this.info.imports) {
      this.moduleScope.vars.set(local, { kind: 'import', ref });
    }
    this.prescan(this.parsed.ast.body, this.moduleScope);
    for (const stmt of this.parsed.ast.body) this.visit(stmt, this.moduleScope);
  }

  // ---- scopes ------------------------------------------------------------

  /** Declares hoisted names (functions, routers, requires) before visiting a block. */
  private prescan(statements: readonly Node[], scope: Scope): void {
    for (const raw of statements) {
      const stmt =
        raw.type === 'ExportNamedDeclaration' || raw.type === 'ExportDefaultDeclaration'
          ? raw.declaration
          : raw;
      if (!stmt) continue;
      if (stmt.type === 'FunctionDeclaration' && stmt.id) {
        scope.vars.set(stmt.id.name, { kind: 'function', node: stmt });
      } else if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations) this.declare(decl, scope);
      }
    }
  }

  private declare(decl: TSESTree.VariableDeclarator, scope: Scope): void {
    const required = requireSource(decl.init);
    if (decl.id.type === 'ObjectPattern' && required) {
      for (const prop of decl.id.properties) {
        if (
          prop.type === 'Property' &&
          prop.key.type === 'Identifier' &&
          prop.value.type === 'Identifier'
        ) {
          scope.vars.set(prop.value.name, {
            kind: 'import',
            ref: { source: required.source, name: prop.key.name },
          });
        }
      }
      return;
    }
    if (decl.id.type !== 'Identifier') return;
    const name = decl.id.name;
    const init = decl.init ? unwrap(decl.init) : null;

    const factory = init ? this.routerFactory(init, scope) : null;
    if (factory) {
      const id = `${this.file}#${name}@${decl.range[0]}`;
      this.routers.set(id, this.newRouter(id, name, factory.framework, factory.isApp, true));
      scope.vars.set(name, { kind: 'router', id });
    } else if (isFunctionNode(init)) {
      scope.vars.set(name, { kind: 'function', node: init });
    } else if (required) {
      scope.vars.set(name, { kind: 'import', ref: required });
    } else if (init?.type === 'Identifier') {
      // `const r = router` aliases
      const target = scope.lookup(init.name);
      scope.vars.set(name, target ?? { kind: 'other' });
    } else {
      scope.vars.set(name, { kind: 'other' });
    }
  }

  /** `express()`, `express.Router()`, `Router()`, `fastify()`, `require('express')()`... */
  private routerFactory(init: Node, scope: Scope): { framework: Framework; isApp: boolean } | null {
    if (init.type !== 'CallExpression') return null;
    const callee = unwrap(init.callee);

    const source = (node: Node): ImportRef | null => {
      if (node.type === 'Identifier') {
        const b = scope.lookup(node.name);
        return b?.kind === 'import' ? b.ref : null;
      }
      return requireSource(node);
    };

    // express() / fastify() / Fastify() / require('express')()
    const direct = source(callee);
    if (direct) {
      if (direct.source === 'express') {
        return direct.name === 'Router'
          ? { framework: 'express', isApp: false }
          : { framework: 'express', isApp: true };
      }
      if (direct.source === 'fastify') return { framework: 'fastify', isApp: true };
    }
    // express.Router() / require('express').Router()
    if (
      callee.type === 'MemberExpression' &&
      !callee.computed &&
      callee.property.type === 'Identifier'
    ) {
      const obj = source(unwrap(callee.object));
      if (obj?.source === 'express' && callee.property.name === 'Router') {
        return { framework: 'express', isApp: false };
      }
    }
    return null;
  }

  private newRouter(
    id: string,
    label: string,
    framework: Framework,
    isApp: boolean,
    gated: boolean,
  ): RouterNode {
    return {
      id,
      file: this.file,
      label,
      framework,
      isApp,
      gated,
      routes: [],
      uses: [],
      mounts: [],
      hooks: [],
    };
  }

  /** Router for a function parameter (`function routes(fastify) {}`, `module.exports = (app) => {}`). */
  private paramRouter(fn: FunctionNode, index: number, name: string): RouterNode {
    const id = paramRouterId(this.file, fn, index);
    let node = this.routers.get(id);
    if (!node) {
      const framework: Framework =
        /^fastify$/i.test(name) || this.framework === 'fastify' ? 'fastify' : 'express';
      node = this.newRouter(
        id,
        name,
        framework,
        false,
        this.framework !== null || /^fastify$/i.test(name),
      );
      this.routers.set(id, node);
    }
    return node;
  }

  // ---- traversal ---------------------------------------------------------

  private visit(node: Node, scope: Scope): void {
    if (isFunctionNode(node)) {
      const fnScope = new Scope(scope);
      node.params.forEach((param, index) => {
        const name = paramName(param);
        if (name) fnScope.vars.set(name, { kind: 'param', fn: node, index, name });
      });
      if (node.body.type === 'BlockStatement') this.prescan(node.body.body, fnScope);
      this.visit(node.body, fnScope);
      return;
    }
    if (node.type === 'CallExpression') this.handleCall(node, scope);
    for (const child of children(node)) this.visit(child, scope);
  }

  private receiver(node: Node, scope: Scope): RouterNode | null {
    const n = unwrap(node);
    if (n.type !== 'Identifier') return null;
    const binding = scope.lookup(n.name);
    if (binding?.kind === 'router') return this.routers.get(binding.id) ?? null;
    if (binding?.kind === 'param') return this.paramRouter(binding.fn, binding.index, binding.name);
    if (binding?.kind === 'import') {
      const id = `${this.file}#import:${n.name}`;
      let alias = this.routers.get(id);
      if (!alias) {
        alias = this.newRouter(id, n.name, this.framework ?? 'express', false, false);
        alias.aliasOf = { kind: 'import', file: this.file, ref: binding.ref, param: 0 };
        this.routers.set(id, alias);
      }
      return alias;
    }
    if (!binding && this.framework && RECEIVER_NAMES.test(n.name)) {
      const id = `${this.file}#global:${n.name}`;
      let node = this.routers.get(id);
      if (!node) {
        // An undeclared `app` in a file that imports express is almost certainly the app itself.
        node = this.newRouter(
          id,
          n.name,
          this.framework,
          /^(?:app|server|fastify)$/i.test(n.name),
          true,
        );
        this.routers.set(id, node);
      }
      return node;
    }
    return null;
  }

  private handleCall(call: TSESTree.CallExpression, scope: Scope): void {
    const callee = call.callee;
    if (
      callee.type !== 'MemberExpression' ||
      callee.computed ||
      callee.property.type !== 'Identifier'
    ) {
      this.handlePlainCall(call, scope);
      return;
    }
    const prop = callee.property.name;
    const method = ROUTE_METHODS[prop];

    // router.route('/x').get(h).post(h)
    if (method && callee.object.type === 'CallExpression') {
      const base = routeChainBase(callee.object);
      if (base) {
        const router = this.receiver(base.receiver, scope);
        if (router) this.addRoute(router, method, base.path, call.arguments, call, scope, true);
      }
      return;
    }

    const router = this.receiver(callee.object, scope);
    if (!router) return;

    if (method) {
      this.addRoute(router, method, call.arguments[0], call.arguments.slice(1), call, scope, false);
    } else if (
      prop === 'route' &&
      call.arguments[0] &&
      unwrap(call.arguments[0]).type === 'ObjectExpression'
    ) {
      this.addFastifyRouteObject(router, call, scope);
    } else if (prop === 'use') {
      this.addUse(router, call, scope);
    } else if (prop === 'register') {
      this.addRegister(router, call, scope);
    } else if (prop === 'addHook') {
      const hook = stringValue(call.arguments[0]);
      if (hook && FASTIFY_AUTH_HOOKS.has(hook) && call.arguments[1]) {
        router.hooks.push(...this.guardsFrom(call.arguments[1], scope));
      }
    }
  }

  private addRoute(
    router: RouterNode,
    method: HttpMethod,
    pathNode: Node | undefined,
    handlerArgs: readonly Node[],
    call: TSESTree.CallExpression,
    scope: Scope,
    isChain: boolean,
  ): void {
    const routePath = pathFrom(pathNode);
    if (routePath === null) {
      // `app.get('env')`-style settings, or a non-literal path on something that may not be a router.
      if (!router.gated || !pathNode || pathNode.type === 'Literal') return;
    } else if (!routePath.startsWith('/') && routePath !== '*') {
      return;
    }

    let handlers = [...handlerArgs];
    const guards: Guard[] = [];
    if (router.framework === 'fastify') {
      const opts = handlers.find((h) => unwrap(h).type === 'ObjectExpression');
      if (opts) {
        const { guards: optGuards, handler } = fastifyOptionGuards(opts, (n) =>
          this.guardsFrom(n, scope),
        );
        guards.push(...optGuards);
        handlers = handlers.filter((h) => h !== opts);
        if (handler) handlers.push(handler);
      }
    }
    const last = handlers.at(-1);
    if (!last || !looksLikeHandler(last)) return;
    if (!isChain && handlerArgs.length === 0) return;

    for (const mw of handlers.slice(0, -1)) guards.push(...this.guardsFrom(mw, scope));

    // `app.all('*', requireAuth)` / `router.get('/admin/*', authenticate)` act as middleware.
    const path = routePath ?? '(dynamic path)';
    const lastGuards = this.guardsFrom(last, scope);
    if (lastGuards.length > 0 && (method === 'ALL' || path.includes('*'))) {
      router.uses.push({
        order: call.range[0],
        prefix: stripWildcard(path),
        guards: [...guards, ...lastGuards],
      });
      return;
    }

    router.routes.push({
      method,
      path,
      order: call.range[0],
      ...position(call),
      guards,
      handler: this.handlerInfo(last, scope),
    });
  }

  private addFastifyRouteObject(
    router: RouterNode,
    call: TSESTree.CallExpression,
    scope: Scope,
  ): void {
    const opts = unwrap(call.arguments[0] as Node);
    if (opts.type !== 'ObjectExpression') return;
    const prop = (key: string) => propertyValue(opts, key);
    const url = pathFrom(prop('url') ?? prop('path'));
    const methodNode = prop('method');
    const methods =
      methodNode && unwrap(methodNode).type === 'ArrayExpression'
        ? (unwrap(methodNode) as TSESTree.ArrayExpression).elements.map((e) =>
            stringValue(e as Node),
          )
        : [stringValue(methodNode)];
    const { guards, handler } = fastifyOptionGuards(opts, (n) => this.guardsFrom(n, scope));
    if (!url || !handler) return;
    for (const m of methods) {
      const method = m ? ROUTE_METHODS[m.toLowerCase()] : undefined;
      if (!method) continue;
      router.routes.push({
        method,
        path: url,
        order: call.range[0],
        ...position(call),
        guards,
        handler: this.handlerInfo(handler, scope),
      });
    }
  }

  private addUse(router: RouterNode, call: TSESTree.CallExpression, scope: Scope): void {
    let args = [...call.arguments] as Node[];
    let prefix = '';
    const first = pathFrom(args[0]);
    if (first !== null) {
      prefix = stripWildcard(first);
      args = args.slice(1);
    }
    const before: Guard[] = [];
    for (const arg of flattenArrays(args)) {
      const target = this.useTarget(arg, scope);
      if (target) {
        const fallback = target.kind === 'import' ? this.guardsFrom(arg, scope)[0] : undefined;
        router.mounts.push({
          order: call.range[0],
          prefix,
          guards: [...before],
          target,
          fallback,
          label: mountLabel(arg),
        });
        continue;
      }
      before.push(...this.guardsFrom(arg, scope));
    }
    if (before.length > 0) router.uses.push({ order: call.range[0], prefix, guards: before });
  }

  /** Express `use` argument that is (or may be) a router. */
  private useTarget(arg: Node, scope: Scope): Ref | null {
    const n = unwrap(arg);
    if (n.type === 'Identifier') {
      const binding = scope.lookup(n.name);
      if (binding?.kind === 'router') return { kind: 'id', id: binding.id };
      if (binding?.kind === 'param') {
        return { kind: 'id', id: this.paramRouter(binding.fn, binding.index, binding.name).id };
      }
      if (
        binding?.kind === 'import' &&
        !this.ctx.isAuth(n.name) &&
        !this.ctx.isAuth(binding.ref.name)
      ) {
        return { kind: 'import', file: this.file, ref: binding.ref, param: 0 };
      }
      return null;
    }
    const required = requireSource(n);
    return required ? { kind: 'import', file: this.file, ref: required, param: 0 } : null;
  }

  private addRegister(router: RouterNode, call: TSESTree.CallExpression, scope: Scope): void {
    let plugin = call.arguments[0] ? unwrap(call.arguments[0]) : null;
    if (!plugin) return;
    // fastify-plugin wrapper: fp(async (fastify) => {...})
    if (
      plugin.type === 'CallExpression' &&
      /^(?:fp|fastifyPlugin)$/.test(lastSegment(dottedName(plugin.callee) ?? ''))
    ) {
      plugin = plugin.arguments[0] ? unwrap(plugin.arguments[0]) : null;
      if (!plugin) return;
    }

    let target: Ref | null = null;
    if (isFunctionNode(plugin)) {
      target = {
        kind: 'id',
        id: this.paramRouter(plugin, 0, paramName(plugin.params[0]) ?? 'fastify').id,
      };
    } else if (plugin.type === 'Identifier') {
      const binding = scope.lookup(plugin.name);
      if (binding?.kind === 'function') {
        target = {
          kind: 'id',
          id: this.paramRouter(binding.node, 0, paramName(binding.node.params[0]) ?? 'fastify').id,
        };
      } else if (binding?.kind === 'router') {
        target = { kind: 'id', id: binding.id };
      } else if (binding?.kind === 'import') {
        target = { kind: 'import', file: this.file, ref: binding.ref, param: 0 };
      }
    } else {
      const required = requireSource(plugin);
      if (required) target = { kind: 'import', file: this.file, ref: required, param: 0 };
    }
    if (!target) return;

    const opts = call.arguments[1] ? unwrap(call.arguments[1]) : null;
    const prefix =
      opts?.type === 'ObjectExpression' ? (pathFrom(propertyValue(opts, 'prefix')) ?? '') : '';
    router.mounts.push({
      order: call.range[0],
      prefix,
      guards: [],
      target,
      label: mountLabel(plugin),
    });
  }

  /** `setupRoutes(app)`, `require('./routes')(app)`: the callee adds routes to `app`. */
  private handlePlainCall(call: TSESTree.CallExpression, scope: Scope): void {
    const callee = unwrap(call.callee);
    call.arguments.forEach((arg, index) => {
      const a = unwrap(arg);
      if (a.type !== 'Identifier') return;
      const binding = scope.lookup(a.name);
      if (binding?.kind !== 'router' && binding?.kind !== 'param') return;
      const router = this.receiver(a, scope);
      if (!router) return;

      let target: Ref | null = null;
      if (callee.type === 'Identifier') {
        const fnBinding = scope.lookup(callee.name);
        if (fnBinding?.kind === 'function') {
          const fn = fnBinding.node;
          target = {
            kind: 'id',
            id: this.paramRouter(fn, index, paramName(fn.params[index]) ?? 'app').id,
          };
        } else if (fnBinding?.kind === 'import') {
          target = { kind: 'import', file: this.file, ref: fnBinding.ref, param: index };
        }
      } else {
        const required = requireSource(callee);
        if (required) target = { kind: 'import', file: this.file, ref: required, param: index };
      }
      if (target) {
        router.mounts.push({
          order: call.range[0],
          prefix: '',
          guards: [],
          target,
          label: mountLabel(callee),
        });
      }
    });
  }

  // ---- guards & handlers ------------------------------------------------

  private evidence(fn: Node): string | null {
    return deepAuthEvidence(this.project, this.file, fn, this.ctx.isAuth);
  }

  guardsFrom(arg: Node, scope: Scope): Guard[] {
    const n = unwrap(arg);
    if (n.type === 'ArrayExpression') {
      return n.elements.flatMap((e) =>
        e && e.type !== 'SpreadElement' ? this.guardsFrom(e, scope) : [],
      );
    }
    const name = dottedName(n);
    if (name && this.ctx.isAuth(name)) return [{ kind: 'known', label: `\`${name}\`` }];

    if (isFunctionNode(n)) {
      const evidence = this.evidence(n);
      return evidence ? [{ kind: 'known', label: `inline middleware that ${evidence}` }] : [];
    }

    // Identifier, or a factory call like `checkRole('admin')`.
    const target = n.type === 'CallExpression' ? unwrap(n.callee) : n;
    if (target.type !== 'Identifier') return [];
    const binding = scope.lookup(target.name);
    if (binding?.kind === 'function') {
      const evidence = this.evidence(binding.node);
      return evidence ? [{ kind: 'known', label: `\`${target.name}\` (${evidence})` }] : [];
    }
    if (binding?.kind === 'import') {
      if (this.ctx.isAuth(binding.ref.name))
        return [{ kind: 'known', label: `\`${target.name}\`` }];
      return [{ kind: 'pending', label: target.name, file: this.file, ref: binding.ref }];
    }
    return [];
  }

  private handlerInfo(node: Node, scope: Scope): HandlerInfo {
    const n = unwrap(node);
    const label = dottedName(n) ?? 'inline handler';
    if (isFunctionNode(n)) return { label, evidence: this.evidence(n), opaque: false };

    if (n.type === 'CallExpression') {
      const name = dottedName(n.callee);
      if (name && this.ctx.isAuth(name))
        return { label, evidence: `is wrapped in \`${name}()\``, opaque: false };
      // asyncHandler(async (req, res) => {...}) / catchAsync(handler)
      const inner = n.arguments[0];
      return inner ? this.handlerInfo(inner, scope) : { label, evidence: null, opaque: true };
    }
    if (n.type === 'Identifier') {
      const binding = scope.lookup(n.name);
      if (binding?.kind === 'function') {
        return { label, evidence: this.evidence(binding.node), opaque: false };
      }
      if (binding?.kind === 'import') {
        return {
          label,
          evidence: null,
          opaque: false,
          pending: { file: this.file, ref: binding.ref },
        };
      }
    }
    return { label, evidence: null, opaque: true };
  }
}

// ---- pass 2 ---------------------------------------------------------------

interface AbsGuard {
  label: string;
  /** Absolute path prefix this guard applies to. */
  prefix: string;
}

export function analyzeExpressFastify(project: JsProject, ctx: EndpointContext): Finding[] {
  const routers = new Map<string, RouterNode>();
  const collectors = new Map<string, FileCollector>();
  for (const parsed of project.files) {
    const info = project.modules.get(parsed.file.path);
    if (!info) continue;
    const collector = new FileCollector(parsed, info, routers, ctx, project);
    collector.run();
    collectors.set(parsed.file.path, collector);
  }

  const linker = new Linker(project, collectors, routers, ctx);
  return linker.findings();
}

class Linker {
  private readonly children = new Map<string, MountDef[]>();
  private readonly hasParent = new Set<string>();
  private readonly guardCache = new Map<string, string | null>();

  constructor(
    private readonly project: JsProject,
    private readonly collectors: ReadonlyMap<string, FileCollector>,
    private readonly routers: ReadonlyMap<string, RouterNode>,
    private readonly ctx: EndpointContext,
  ) {
    // `import app from './app'; app.get(...)` behaves like a mount at the end of `app`.
    for (const node of routers.values()) {
      if (!node.aliasOf) continue;
      const target = this.resolve(node.aliasOf);
      const targetNode = target ? routers.get(target) : undefined;
      if (targetNode) {
        targetNode.mounts.push({
          order: Infinity,
          prefix: '',
          guards: [],
          target: { kind: 'id', id: node.id },
        });
        node.framework = targetNode.framework;
      }
    }

    for (const node of routers.values()) {
      for (const mount of node.mounts) {
        const childId = this.resolve(mount.target);
        if (childId && childId !== node.id && routers.has(childId)) {
          this.hasParent.add(childId);
          this.children.set(node.id, [
            ...(this.children.get(node.id) ?? []),
            { ...mount, target: { kind: 'id', id: childId } },
          ]);
        } else if (mount.fallback) {
          // Not a router after all, so it was middleware: `app.use(importedMiddleware)`.
          node.uses.push({ order: mount.order, prefix: mount.prefix, guards: [mount.fallback] });
        }
      }
    }
  }

  findings(): Finding[] {
    const out = new Map<string, Finding>();
    for (const node of this.routers.values()) {
      if (this.hasParent.has(node.id) || !node.gated || node.aliasOf) continue;
      this.visit(
        node,
        { prefix: '', guards: [], chain: [node.label], mounted: node.isApp },
        new Set(),
        out,
      );
    }
    return [...out.values()];
  }

  private visit(
    node: RouterNode,
    ctx: { prefix: string; guards: AbsGuard[]; chain: string[]; mounted: boolean },
    stack: Set<string>,
    out: Map<string, Finding>,
  ): void {
    if (stack.has(node.id)) return;
    stack.add(node.id);

    const hooks = this.labels(node.hooks).map((label) => ({ label, prefix: ctx.prefix || '/' }));
    const usesBefore = (order: number) =>
      node.uses
        .filter((u) => u.order < order || node.framework === 'fastify')
        .flatMap((u) =>
          this.labels(u.guards).map((label) => ({ label, prefix: joinPath(ctx.prefix, u.prefix) })),
        );

    for (const route of node.routes) {
      const fullPath = joinPath(ctx.prefix, route.path);
      const applicable = [...ctx.guards, ...hooks, ...usesBefore(route.order)].filter((g) =>
        prefixMatches(g.prefix, fullPath),
      );
      if (applicable.length > 0 || this.labels(route.guards).length > 0) continue;
      const handlerEvidence = this.handlerEvidence(route.handler);
      if (handlerEvidence) continue;
      if (this.ctx.isPublic(fullPath)) continue;

      const finding = this.toFinding(node, route, fullPath, ctx.chain, ctx.mounted);
      if (!out.has(finding.fingerprint)) out.set(finding.fingerprint, finding);
    }

    for (const mount of this.children.get(node.id) ?? []) {
      const child = this.routers.get((mount.target as { id: string }).id);
      if (!child) continue;
      const prefix = joinPath(ctx.prefix, mount.prefix);
      const guards = [
        ...ctx.guards,
        ...hooks,
        ...usesBefore(mount.order),
        ...this.labels(mount.guards).map((label) => ({ label, prefix: prefix || '/' })),
      ];
      const name = mount.label ?? child.label;
      const where = child.file === node.file ? name : `${name} in ${child.file}`;
      const step = mount.prefix ? `${mount.prefix}: ${where}` : where;
      this.visit(child, { prefix, guards, chain: [...ctx.chain, step], mounted: true }, stack, out);
    }
    stack.delete(node.id);
  }

  private toFinding(
    node: RouterNode,
    route: RouteDef,
    fullPath: string,
    chain: string[],
    mounted: boolean,
  ): Finding {
    const risk = assessEndpointRisk(route.method, fullPath);
    const ruleId = `endpoint/${node.framework}-unprotected-route`;
    const where =
      node.framework === 'fastify'
        ? `no auth hook (\`onRequest\`/\`preHandler\`) on the route or on the plugin chain ${chain.map((c) => `\`${c}\``).join(' → ')}`
        : `no auth middleware on the route or registered before it on ${chain.map((c) => `\`${c}\``).join(' → ')}`;
    const notes: string[] = [];
    const pending = route.handler.pending;
    if (pending && !resolveImportedFunction(this.project, pending.file, pending.ref)) {
      notes.push(
        `The handler \`${route.handler.label}\` is imported from \`${pending.ref.source}\`, which leakroute could not resolve, so its body was not checked.`,
      );
    } else if (route.handler.opaque) {
      notes.push(
        `The handler \`${route.handler.label}\` is defined somewhere leakroute could not follow, so its body was not checked.`,
      );
    }
    if (!mounted) {
      notes.push(
        `\`${node.label}\` is not mounted anywhere leakroute could find, so auth added where it is mounted is not visible.`,
      );
    }
    const reason = [
      `No authentication found for \`${route.method} ${fullPath}\`: ${where}, and the handler does not call a known auth function or respond 401/403.`,
      risk.why,
      ...notes,
    ].join(' ');

    return {
      ruleId,
      category: 'endpoint',
      severity: risk.severity,
      file: node.file,
      line: route.line,
      column: route.column,
      title: `Possible unprotected endpoint: ${route.method} ${fullPath}`,
      reason,
      remediation:
        node.framework === 'fastify'
          ? "Add `onRequest: [fastify.authenticate]` (or `preHandler`) to the route options, or `fastify.addHook('onRequest', ...)` in the plugin that registers it. If the route is meant to be public, add it to `public-routes` in .leakroute.yml; if your auth hook has a custom name, add it to `auth-middleware`."
          : "Add auth middleware to the route (`router.post('/x', requireAuth, handler)`) or protect the whole router with `router.use(requireAuth)` before its routes. If the route is meant to be public, add it to `public-routes` in .leakroute.yml; if your middleware has a custom name, add it to `auth-middleware`.",
      fingerprint: fingerprint(ruleId, node.file, route.method, fullPath),
    };
  }

  // ---- resolution -----------------------------------------------------

  private labels(guards: readonly Guard[]): string[] {
    return guards.flatMap((g) => {
      if (g.kind === 'known') return [g.label];
      const resolved = this.resolvePendingGuard(g);
      return resolved ? [resolved] : [];
    });
  }

  private resolvePendingGuard(g: Extract<Guard, { kind: 'pending' }>): string | null {
    const key = `${g.file}\u0000${g.ref.source}\u0000${g.ref.name}`;
    if (!this.guardCache.has(key)) {
      const evidence = this.importedEvidence(g.file, g.ref);
      this.guardCache.set(key, evidence ? `\`${g.label}\` (${evidence})` : null);
    }
    return this.guardCache.get(key) ?? null;
  }

  private handlerEvidence(handler: HandlerInfo): string | null {
    if (handler.evidence || !handler.pending) return handler.evidence;
    return this.importedEvidence(handler.pending.file, handler.pending.ref);
  }

  private importedEvidence(fromFile: string, ref: ImportRef): string | null {
    const resolved = resolveImportedFunction(this.project, fromFile, ref);
    return resolved
      ? deepAuthEvidence(this.project, resolved.file, resolved.fn, this.ctx.isAuth)
      : null;
  }

  private resolve(ref: Ref, depth = 0): string | null {
    if (ref.kind === 'id') return ref.id;
    if (depth > 5) return null;
    const target = resolveModule(ref.file, ref.ref.source, this.project.paths);
    const collector = target ? this.collectors.get(target) : undefined;
    if (!target || !collector) return null;
    const exported = collector.info.exports.get(ref.ref.name);
    if (!exported) return null;

    let n = unwrap(exported);
    if (
      n.type === 'CallExpression' &&
      /^(?:fp|fastifyPlugin)$/.test(lastSegment(dottedName(n.callee) ?? ''))
    ) {
      n = n.arguments[0] ? unwrap(n.arguments[0]) : n;
    }
    if (isFunctionNode(n)) return paramRouterId(target, n, ref.param);
    if (n.type === 'Identifier') {
      const binding = collector.moduleScope.lookup(n.name);
      if (binding?.kind === 'router') return binding.id;
      if (binding?.kind === 'function') return paramRouterId(target, binding.node, ref.param);
      if (binding?.kind === 'import') {
        return this.resolve(
          { kind: 'import', file: target, ref: binding.ref, param: ref.param },
          depth + 1,
        );
      }
    }
    return null;
  }
}

// ---- helpers ----------------------------------------------------------------

function paramRouterId(file: string, fn: FunctionNode, index: number): string {
  return `${file}#fn${fn.range[0]}:${index}`;
}

function mountLabel(node: Node): string | undefined {
  const n = unwrap(node);
  if (isFunctionNode(n)) return 'inline plugin';
  return dottedName(n) ?? requireSource(n)?.source ?? undefined;
}

function paramName(param: Node | undefined): string | null {
  if (!param) return null;
  if (param.type === 'Identifier') return param.name;
  if (param.type === 'AssignmentPattern' && param.left.type === 'Identifier')
    return param.left.name;
  if (param.type === 'TSParameterProperty' && param.parameter.type === 'Identifier')
    return param.parameter.name;
  return null;
}

function routeChainBase(
  call: TSESTree.CallExpression,
): { receiver: Node; path: Node | undefined } | null {
  let current: Node = call;
  while (current.type === 'CallExpression') {
    const callee: TSESTree.Expression = current.callee;
    if (
      callee.type !== 'MemberExpression' ||
      callee.computed ||
      callee.property.type !== 'Identifier'
    )
      return null;
    if (callee.property.name === 'route')
      return { receiver: callee.object, path: current.arguments[0] };
    if (!ROUTE_METHODS[callee.property.name]) return null;
    current = callee.object;
  }
  return null;
}

function pathFrom(node: Node | undefined | null): string | null {
  if (!node) return null;
  const n = unwrap(node);
  if (n.type === 'ArrayExpression') {
    const first = n.elements.find((e) => e && stringValue(e as Node) !== null);
    return first ? stringValue(first as Node) : null;
  }
  return stringValue(n);
}

export function propertyValue(obj: TSESTree.ObjectExpression, key: string): Node | undefined {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property') continue;
    const name = prop.key.type === 'Identifier' ? prop.key.name : stringValue(prop.key);
    if (name === key) return prop.value;
  }
  return undefined;
}

function flattenArrays(args: readonly Node[]): Node[] {
  return args.flatMap((a) => {
    const n = unwrap(a);
    return n.type === 'ArrayExpression'
      ? flattenArrays(
          n.elements.filter((e): e is TSESTree.Expression => !!e && e.type !== 'SpreadElement'),
        )
      : [a];
  });
}

function looksLikeHandler(node: Node): boolean {
  const n = unwrap(node);
  return (
    isFunctionNode(n) ||
    n.type === 'Identifier' ||
    n.type === 'MemberExpression' ||
    n.type === 'CallExpression' ||
    n.type === 'ArrayExpression'
  );
}

function stripWildcard(p: string): string {
  const stripped = p.replace(/\/?\(\.\*\)$/, '').replace(/\/?\*+$/, '');
  return stripped === '' ? '/' : stripped;
}

export function joinPath(prefix: string, sub: string): string {
  const joined = `/${prefix}/${sub}`.replace(/\/{2,}/g, '/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : joined;
}

function prefixMatches(prefix: string, fullPath: string): boolean {
  if (prefix === '' || prefix === '/') return true;
  const p = prefix.replace(/\/$/, '');
  return fullPath === p || fullPath.startsWith(`${p}/`);
}

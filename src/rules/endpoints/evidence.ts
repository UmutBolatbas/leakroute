import {
  isFunctionNode,
  unwrap,
  walk,
  type FunctionNode,
  type Node,
} from '../../parsers/javascript.js';
import { findAuthEvidence, type AuthMatcher } from './auth.js';
import { resolveModule, type ImportRef } from './modules.js';
import type { JsProject } from './types.js';

const MAX_DEPTH = 2;

export interface ResolvedFunction {
  fn: FunctionNode;
  file: string;
}

/** Follows an import (through re-exports) to the function it names. */
export function resolveImportedFunction(
  project: JsProject,
  fromFile: string,
  ref: ImportRef,
  depth = 0,
): ResolvedFunction | null {
  if (depth > 5) return null;
  const target = resolveModule(fromFile, ref.source, project.paths);
  const info = target ? project.modules.get(target) : undefined;
  if (!target || !info) return null;
  const exported = info.exports.get(ref.name);
  if (!exported) return null;
  return functionFromNode(project, target, exported, depth);
}

/** Resolves a local expression (function, identifier, wrapper call) to a function. */
export function functionFromNode(
  project: JsProject,
  file: string,
  node: Node,
  depth = 0,
): ResolvedFunction | null {
  const info = project.modules.get(file);
  const n = unwrap(node);
  if (isFunctionNode(n)) return { fn: n, file };
  if (n.type === 'Identifier' && info) {
    const local = info.functions.get(n.name);
    if (local) return { fn: local, file };
    const variable = info.variables.get(n.name);
    if (variable && variable !== node) return functionFromNode(project, file, variable, depth + 1);
    const imported = info.imports.get(n.name);
    if (imported) return resolveImportedFunction(project, file, imported, depth + 1);
  }
  if (n.type === 'CallExpression') {
    // `createMiddleware(async (req, next) => {...})`: the function argument does the work.
    const inner = n.arguments.find((a) => isFunctionNode(unwrap(a)));
    if (inner) return { fn: unwrap(inner) as FunctionNode, file };
  }
  return null;
}

/**
 * Like `findAuthEvidence`, but also follows calls to local and imported helper
 * functions, so `const user = await requireCurrentUser()` counts when that helper
 * calls `getServerSession()`.
 */
export function deepAuthEvidence(
  project: JsProject,
  file: string,
  fn: Node,
  isAuth: AuthMatcher,
  depth = 0,
  seen: Set<Node> = new Set(),
): string | null {
  if (seen.has(fn)) return null;
  seen.add(fn);

  const direct = findAuthEvidence(fn, isAuth);
  if (direct || depth >= MAX_DEPTH) return direct;

  const info = project.modules.get(file);
  let evidence: string | null = null;
  walk(fn, (node) => {
    if (evidence) return false;
    if (node.type !== 'CallExpression') return undefined;
    const callee = unwrap(node.callee);
    if (callee.type !== 'Identifier') return undefined;

    let helper: ResolvedFunction | null = null;
    const local = info?.functions.get(callee.name);
    if (local) helper = { fn: local, file };
    else {
      const imported = info?.imports.get(callee.name);
      if (imported) helper = resolveImportedFunction(project, file, imported);
    }
    if (!helper) return undefined;

    const inner = deepAuthEvidence(project, helper.file, helper.fn, isAuth, depth + 1, seen);
    if (inner) evidence = `calls \`${callee.name}()\`, which ${inner}`;
    return undefined;
  });
  return evidence;
}

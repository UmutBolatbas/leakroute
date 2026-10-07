import { parse, type TSESTree } from '@typescript-eslint/typescript-estree';
import type { SourceFile } from '../core/types.js';

export type { TSESTree };
export type Node = TSESTree.Node;
export type FunctionNode =
  TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;

const JS_FILE = /\.(?:[cm]?[jt]sx?)$/i;

export function isJsFile(path: string): boolean {
  return JS_FILE.test(path) && !/\.d\.[cm]?ts$/i.test(path);
}

export interface ParsedJs {
  file: SourceFile;
  ast: TSESTree.Program;
}

/** Parses JS/TS/JSX. Returns `null` for files that don't parse (they are skipped, not fatal). */
export function parseJs(file: SourceFile): ParsedJs | null {
  // `<T>value` casts are ambiguous with JSX, so only enable JSX where it can appear.
  const jsx = !/\.[cm]?ts$/i.test(file.path);
  for (const attempt of jsx ? [true, false] : [false]) {
    try {
      const ast = parse(file.content, {
        jsx: attempt,
        loc: true,
        range: true,
        comment: false,
        tokens: false,
        errorOnUnknownASTType: false,
      });
      return { file, ast };
    } catch {
      // try the next mode
    }
  }
  return null;
}

/** Strips wrappers that don't change what an expression refers to. */
export function unwrap(node: Node): Node {
  let current = node;
  for (;;) {
    switch (current.type) {
      case 'AwaitExpression':
        current = current.argument;
        break;
      case 'TSAsExpression':
      case 'TSNonNullExpression':
      case 'TSSatisfiesExpression':
      case 'TSTypeAssertion':
      case 'ChainExpression':
        current = current.expression;
        break;
      default:
        return current;
    }
  }
}

/**
 * Dotted name of an identifier/member chain: `passport.authenticate`, `req.auth.getUser`.
 * For calls, the callee's name: `passport.authenticate('jwt')` -> `passport.authenticate`.
 */
export function dottedName(node: Node | null | undefined): string | null {
  if (!node) return null;
  const n = unwrap(node);
  switch (n.type) {
    case 'Identifier':
      return n.name;
    case 'ThisExpression':
      return 'this';
    case 'MemberExpression': {
      if (n.computed) return null;
      const object = dottedName(n.object);
      const property = n.property.type === 'Identifier' ? n.property.name : null;
      return object && property ? `${object}.${property}` : property;
    }
    case 'CallExpression':
      return dottedName(n.callee);
    default:
      return null;
  }
}

export function lastSegment(name: string): string {
  return name.slice(name.lastIndexOf('.') + 1);
}

/** Value of a string literal or a template literal without expressions. */
export function stringValue(node: Node | null | undefined): string | null {
  if (!node) return null;
  const n = unwrap(node);
  if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
  if (n.type === 'TemplateLiteral' && n.expressions.length === 0) {
    return n.quasis.map((q) => q.value.cooked ?? q.value.raw).join('');
  }
  return null;
}

export function isFunctionNode(node: Node | null | undefined): node is FunctionNode {
  return (
    node?.type === 'FunctionDeclaration' ||
    node?.type === 'FunctionExpression' ||
    node?.type === 'ArrowFunctionExpression'
  );
}

/**
 * Depth-first walk. Returning `false` from `enter` skips the node's children;
 * `leave` runs after the children.
 */
export function walk(
  root: Node,
  enter: (node: Node, parent: Node | null) => unknown,
  leave?: (node: Node) => void,
): void {
  const visit = (node: Node, parent: Node | null) => {
    if (enter(node, parent) === false) return;
    for (const child of children(node)) visit(child, node);
    leave?.(node);
  };
  visit(root, null);
}

/** Direct child nodes, in source order. */
export function children(node: Node): Node[] {
  const out: Node[] = [];
  for (const key of Object.keys(node)) {
    if (key === 'parent' || key === 'loc' || key === 'range') continue;
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const child of value) if (isNode(child)) out.push(child);
    } else if (isNode(value)) {
      out.push(value);
    }
  }
  return out;
}

function isNode(value: unknown): value is Node {
  return typeof value === 'object' && value !== null && typeof (value as Node).type === 'string';
}

export function position(node: Node): { line: number; column: number } {
  return { line: node.loc.start.line, column: node.loc.start.column + 1 };
}

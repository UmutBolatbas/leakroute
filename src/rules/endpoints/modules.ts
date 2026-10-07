import path from 'node:path';
import {
  dottedName,
  isFunctionNode,
  stringValue,
  unwrap,
  type FunctionNode,
  type Node,
  type ParsedJs,
  type TSESTree,
} from '../../parsers/javascript.js';

/** `local` was imported as `name` (`'default'` for default imports) from `source`. */
export interface ImportRef {
  source: string;
  name: string;
}

/**
 * Module-level facts about one JS/TS file: what it imports, what it exports and
 * which named functions it declares. Shared by the Express/Fastify and Next.js rules.
 */
export interface ModuleInfo {
  file: string;
  imports: Map<string, ImportRef>;
  /** Exported name (`'default'` included) -> the exported expression or declaration. */
  exports: Map<string, Node>;
  /** Module-scope functions by name (declarations and `const f = () => {}`). */
  functions: Map<string, FunctionNode>;
  /** Module-scope `const x = <init>` by name. */
  variables: Map<string, Node>;
}

export function collectModuleInfo(parsed: ParsedJs): ModuleInfo {
  const info: ModuleInfo = {
    file: parsed.file.path,
    imports: new Map(),
    exports: new Map(),
    functions: new Map(),
    variables: new Map(),
  };

  const declare = (decl: TSESTree.VariableDeclarator) => {
    if (decl.id.type === 'Identifier' && decl.init) {
      info.variables.set(decl.id.name, decl.init);
      const init = unwrap(decl.init);
      if (isFunctionNode(init)) info.functions.set(decl.id.name, init);
    }
    const required = requireSource(decl.init);
    if (required) {
      if (decl.id.type === 'Identifier') {
        info.imports.set(decl.id.name, { source: required.source, name: required.name });
      } else if (decl.id.type === 'ObjectPattern') {
        for (const prop of decl.id.properties) {
          if (prop.type !== 'Property' || prop.key.type !== 'Identifier') continue;
          const local = prop.value.type === 'Identifier' ? prop.value.name : null;
          if (local) info.imports.set(local, { source: required.source, name: prop.key.name });
        }
      }
    }
  };

  const declareStatement = (stmt: Node) => {
    if (stmt.type === 'VariableDeclaration') stmt.declarations.forEach(declare);
    if (stmt.type === 'FunctionDeclaration' && stmt.id) info.functions.set(stmt.id.name, stmt);
  };

  for (const stmt of parsed.ast.body) {
    switch (stmt.type) {
      case 'ImportDeclaration': {
        const source = String(stmt.source.value);
        for (const spec of stmt.specifiers) {
          const name =
            spec.type === 'ImportDefaultSpecifier'
              ? 'default'
              : spec.type === 'ImportNamespaceSpecifier'
                ? '*'
                : spec.imported.type === 'Identifier'
                  ? spec.imported.name
                  : String(spec.imported.value);
          info.imports.set(spec.local.name, { source, name });
        }
        break;
      }
      case 'ExportNamedDeclaration': {
        if (stmt.declaration) {
          declareStatement(stmt.declaration);
          if (stmt.declaration.type === 'VariableDeclaration') {
            for (const d of stmt.declaration.declarations) {
              if (d.id.type === 'Identifier' && d.init) info.exports.set(d.id.name, d.init);
            }
          } else if (stmt.declaration.type === 'FunctionDeclaration' && stmt.declaration.id) {
            info.exports.set(stmt.declaration.id.name, stmt.declaration);
          }
        }
        for (const spec of stmt.specifiers) {
          if (spec.type !== 'ExportSpecifier') continue;
          const exported =
            spec.exported.type === 'Identifier' ? spec.exported.name : String(spec.exported.value);
          if (spec.local.type !== 'Identifier') continue;
          if (stmt.source) {
            // Re-export: `export { a as b } from './x'` behaves like importing `a`.
            info.imports.set(spec.local.name, {
              source: String(stmt.source.value),
              name: spec.local.name,
            });
          }
          info.exports.set(exported, spec.local);
        }
        break;
      }
      case 'ExportDefaultDeclaration':
        info.exports.set('default', stmt.declaration);
        if (stmt.declaration.type === 'FunctionDeclaration' && stmt.declaration.id) {
          info.functions.set(stmt.declaration.id.name, stmt.declaration);
        }
        break;
      case 'ExpressionStatement':
        collectCommonJsExport(stmt.expression, info);
        break;
      default:
        declareStatement(stmt);
    }
  }
  return info;
}

/** `module.exports = x`, `module.exports = { a, b }`, `exports.a = x`, `module.exports.a = x`. */
function collectCommonJsExport(expr: Node, info: ModuleInfo): void {
  if (expr.type !== 'AssignmentExpression' || expr.operator !== '=') return;
  const target = dottedName(expr.left);
  if (target === 'module.exports') {
    const value = unwrap(expr.right);
    if (value.type === 'ObjectExpression') {
      for (const prop of value.properties) {
        if (prop.type === 'Property' && prop.key.type === 'Identifier') {
          info.exports.set(prop.key.name, prop.value);
        }
      }
    }
    info.exports.set('default', expr.right);
  } else if (target?.startsWith('module.exports.') || target?.startsWith('exports.')) {
    info.exports.set(target.slice(target.lastIndexOf('.') + 1), expr.right);
  }
}

/** `require('x')`, `require('x').default`, `require('x').Router` -> source + imported name. */
export function requireSource(node: Node | null | undefined): ImportRef | null {
  if (!node) return null;
  const n = unwrap(node);
  if (
    n.type === 'CallExpression' &&
    n.callee.type === 'Identifier' &&
    n.callee.name === 'require'
  ) {
    const source = stringValue(n.arguments[0]);
    return source === null ? null : { source, name: 'default' };
  }
  if (n.type === 'ImportExpression') {
    const source = stringValue(n.source);
    return source === null ? null : { source, name: 'default' };
  }
  if (n.type === 'MemberExpression' && !n.computed && n.property.type === 'Identifier') {
    const inner = requireSource(n.object);
    if (inner) return { source: inner.source, name: n.property.name };
  }
  return null;
}

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];

/**
 * Resolves a relative (or `@/`, `~/` aliased) import to a scanned file.
 * Package imports return `null`: we only follow code inside the repository.
 */
export function resolveModule(
  fromFile: string,
  source: string,
  files: ReadonlySet<string>,
): string | null {
  let bases: string[];
  if (source.startsWith('.')) {
    bases = [path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), source))];
  } else if (source.startsWith('@/') || source.startsWith('~/')) {
    const rest = source.slice(2);
    // Aliases usually point at `src/` or the project root, possibly in a monorepo package.
    const pkgRoot = fromFile.includes('/src/')
      ? fromFile.slice(0, fromFile.indexOf('/src/') + 1)
      : '';
    bases = [`${pkgRoot}src/${rest}`, `${pkgRoot}${rest}`, `src/${rest}`, rest];
  } else {
    return null;
  }

  for (const base of bases) {
    const stripped = base.replace(/\.(?:[cm]?js|jsx)$/, '');
    const candidates = [
      base,
      ...EXTENSIONS.map((ext) => stripped + ext),
      ...EXTENSIONS.map((ext) => `${stripped}/index${ext}`),
    ];
    const hit = candidates.find((c) => files.has(c));
    if (hit) return hit;
  }
  return null;
}

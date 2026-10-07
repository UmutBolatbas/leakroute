import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Language, Parser, type Node, type Tree } from 'web-tree-sitter';
import type { SourceFile } from '../core/types.js';

export type PyNode = Node;

export interface ParsedPy {
  file: SourceFile;
  tree: Tree;
  root: PyNode;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const GRAMMAR = 'tree-sitter-python.wasm';

/**
 * Finds a bundled WASM file. Locations differ between running from source
 * (`src/parsers`), the npm package (`lib/parsers`) and the bundled GitHub Action
 * (`dist/`), so we try each.
 */
function findAsset(name: string, extra: readonly string[] = []): string {
  const candidates = [
    path.join(here, name),
    path.join(here, 'grammars', name),
    path.join(here, '..', 'vendor', 'grammars', name),
    path.join(here, '..', '..', 'vendor', 'grammars', name),
    ...extra,
  ];
  const found = candidates.find((c) => existsSync(c));
  if (!found)
    throw new Error(`leakroute: could not find ${name} (looked in ${candidates.join(', ')})`);
  return found;
}

function runtimeWasm(): string {
  const fromPackage: string[] = [];
  try {
    fromPackage.push(
      createRequire(import.meta.url).resolve('web-tree-sitter/web-tree-sitter.wasm'),
    );
  } catch {
    // bundled: the file sits next to the bundle instead
  }
  return findAsset('web-tree-sitter.wasm', fromPackage);
}

let parserPromise: Promise<Parser> | null = null;

/** Loads the WASM runtime and the Python grammar once per process. */
export function getPythonParser(): Promise<Parser> {
  parserPromise ??= (async () => {
    const wasm = runtimeWasm();
    await Parser.init({ locateFile: () => wasm });
    const language = await Language.load(findAsset(GRAMMAR));
    const parser = new Parser();
    parser.setLanguage(language);
    return parser;
  })();
  return parserPromise;
}

export function isPythonFile(file: string): boolean {
  return /\.pyw?$/i.test(file);
}

/** Parses a file. Returns `null` when the tree has syntax errors at the top level. */
export function parsePython(parser: Parser, file: SourceFile): ParsedPy | null {
  const tree = parser.parse(file.content);
  if (!tree) return null;
  return { file, tree, root: tree.rootNode };
}

// ---- helpers --------------------------------------------------------------

/** `app.get` -> "app.get", `auth.login_required` -> "auth.login_required", call -> its function. */
export function pyDotted(node: PyNode | null | undefined): string | null {
  if (!node) return null;
  switch (node.type) {
    case 'identifier':
      return node.text;
    case 'attribute': {
      const object = pyDotted(node.childForFieldName('object'));
      const attr = node.childForFieldName('attribute')?.text;
      return object && attr ? `${object}.${attr}` : (attr ?? null);
    }
    case 'call':
      return pyDotted(node.childForFieldName('function'));
    case 'parenthesized_expression':
    case 'await':
      return pyDotted(node.namedChildren[0]);
    default:
      return null;
  }
}

/** Value of a plain string literal; `null` for f-strings with interpolation or non-strings. */
export function pyString(node: PyNode | null | undefined): string | null {
  if (!node) return null;
  if (node.type === 'concatenated_string') {
    const parts = node.namedChildren.map((c) => pyString(c));
    return parts.every((p) => p !== null) ? parts.join('') : null;
  }
  if (node.type !== 'string') return null;
  if (node.namedChildren.some((c) => c.type === 'interpolation')) return null;
  return node.namedChildren
    .filter((c) => c.type === 'string_content' || c.type === 'escape_sequence')
    .map((c) => c.text)
    .join('');
}

export interface PyArgs {
  positional: PyNode[];
  keywords: Map<string, PyNode>;
}

export function pyArgs(call: PyNode): PyArgs {
  const out: PyArgs = { positional: [], keywords: new Map() };
  const list = call.childForFieldName('arguments');
  for (const arg of list?.namedChildren ?? []) {
    if (arg.type === 'keyword_argument') {
      const name = arg.childForFieldName('name')?.text;
      const value = arg.childForFieldName('value');
      if (name && value) out.keywords.set(name, value);
    } else if (arg.type !== 'comment') {
      out.positional.push(arg);
    }
  }
  return out;
}

/** Strings in a list/tuple literal (`methods=["GET", "POST"]`). */
export function pyStringList(node: PyNode | null | undefined): string[] {
  if (!node) return [];
  if (node.type === 'list' || node.type === 'tuple' || node.type === 'set') {
    return node.namedChildren.map((c) => pyString(c)).filter((s): s is string => s !== null);
  }
  const single = pyString(node);
  return single === null ? [] : [single];
}

/** Pre-order walk. Returning `false` skips the node's children. */
export function walkPy(node: PyNode, enter: (node: PyNode) => unknown): void {
  if (enter(node) === false) return;
  for (const child of node.namedChildren) walkPy(child, enter);
}

export function pyPosition(node: PyNode): { line: number; column: number } {
  return { line: node.startPosition.row + 1, column: node.startPosition.column + 1 };
}

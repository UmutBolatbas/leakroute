import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import ignore, { type Ignore } from 'ignore';
import picomatch from 'picomatch';
import type { SourceFile } from './types.js';

const execFileAsync = promisify(execFile);

/** Directories that are never worth scanning (dependencies, build caches, VCS internals). */
export const DEFAULT_IGNORED_DIRS: ReadonlySet<string> = new Set([
  '.git',
  'node_modules',
  'bower_components',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
]);

/** Generated files that are large, noisy and full of harmless high-entropy strings. */
const DEFAULT_IGNORED_FILES = picomatch(
  [
    '**/package-lock.json',
    '**/npm-shrinkwrap.json',
    '**/yarn.lock',
    '**/pnpm-lock.yaml',
    '**/bun.lockb',
    '**/poetry.lock',
    '**/Pipfile.lock',
    '**/uv.lock',
    '**/Cargo.lock',
    '**/go.sum',
    '**/composer.lock',
    '**/*.min.js',
    '**/*.min.css',
    '**/*.map',
  ],
  { dot: true },
);

export interface ListFilesOptions {
  ignorePaths: readonly string[];
}

/**
 * Lists files under `root` as repo-relative POSIX paths.
 *
 * Inside a git work tree this asks git, so only files that are (or are about to be)
 * committed are scanned and every `.gitignore` is honoured exactly. Outside git it
 * walks the directory tree and applies `.gitignore` files itself.
 */
export async function listFiles(root: string, options: ListFilesOptions): Promise<string[]> {
  const all = (await listGitFiles(root)) ?? (await walk(root));
  return all.filter(createPathFilter(options.ignorePaths)).sort();
}

/** Returns a predicate that is `true` for repo-relative paths that should be scanned. */
export function createPathFilter(ignorePaths: readonly string[]): (rel: string) => boolean {
  const isUserIgnored = ignorePaths.length > 0 ? picomatch([...ignorePaths], { dot: true }) : null;
  return (rel) => {
    const segments = rel.split('/');
    if (segments.slice(0, -1).some((s) => DEFAULT_IGNORED_DIRS.has(s))) return false;
    if (DEFAULT_IGNORED_FILES(rel)) return false;
    if (isUserIgnored?.(rel)) return false;
    return true;
  };
}

async function listGitFiles(root: string): Promise<string[] | null> {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
      { cwd: root, maxBuffer: 256 * 1024 * 1024 },
    );
    // --cached also lists files deleted from the working tree but not yet staged.
    return stdout.split('\0').filter((rel) => rel.length > 0 && existsSync(path.join(root, rel)));
  } catch {
    return null;
  }
}

async function walk(root: string): Promise<string[]> {
  const out: string[] = [];

  async function visit(relDir: string, rules: readonly Ignore[]): Promise<void> {
    const absDir = path.join(root, relDir);
    const entries = await readdir(absDir, { withFileTypes: true }).catch(() => []);

    let scoped = rules;
    if (entries.some((e) => e.isFile() && e.name === '.gitignore')) {
      const text = await readFile(path.join(absDir, '.gitignore'), 'utf8').catch(() => '');
      scoped = [...rules, Object.assign(ignore().add(text), { base: relDir })];
    }

    for (const entry of entries) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name) || isGitIgnored(scoped, `${rel}/`)) continue;
        await visit(rel, scoped);
      } else if (entry.isFile() && !isGitIgnored(scoped, rel)) {
        out.push(rel);
      }
    }
  }

  await visit('', []);
  return out;
}

function isGitIgnored(rules: readonly Ignore[], rel: string): boolean {
  return rules.some((rule) => {
    const base = (rule as Ignore & { base: string }).base;
    if (!base) return rule.ignores(rel);
    return rel.startsWith(`${base}/`) && rule.ignores(rel.slice(base.length + 1));
  });
}

/**
 * Reads a text file. Returns `null` for files that are too large or look binary
 * (a NUL byte in the first 8 KB, the same heuristic git uses).
 */
export async function readSourceFile(
  root: string,
  rel: string,
  maxFileSize: number,
): Promise<SourceFile | null> {
  const absPath = path.join(root, rel);
  try {
    const info = await stat(absPath);
    if (!info.isFile() || info.size > maxFileSize) return null;
    const buf = await readFile(absPath);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return { path: rel, absPath, content: buf.toString('utf8') };
  } catch {
    return null;
  }
}

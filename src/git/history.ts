import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { scanSensitiveFile, scanTextForSecrets } from '../rules/secrets/index.js';
import type { Finding } from '../core/types.js';

export interface HistoryScanOptions {
  /** Same predicate the working-tree scan uses, so ignore-paths apply to history too. */
  shouldScan: (rel: string) => boolean;
}

/**
 * Scans every line ever added in any commit reachable from any ref.
 *
 * Runs `git log -p` once and streams it, so memory stays flat on large repos.
 * Each secret is reported once, for the most recent commit that added it.
 */
export async function scanGitHistory(
  root: string,
  options: HistoryScanOptions,
): Promise<Finding[]> {
  const child = spawn(
    'git',
    [
      '-c',
      'core.quotepath=false',
      'log',
      '-p',
      '--all',
      '--relative',
      '--no-color',
      '--no-ext-diff',
      '--no-renames',
      '--unified=0',
      '--format=%x00commit %H',
    ],
    { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] },
  );

  let stderr = '';
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const exited = new Promise<number>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve(code ?? 1));
  });

  const findings = new Map<string, Finding>();
  let commit = '';
  let file: string | null = null;
  let isNewFile = false;
  let nextLine = 0;
  let lines: string[] = [];
  let lineNumbers: number[] = [];

  const flush = () => {
    if (file && options.shouldScan(file)) {
      const text = lines.join('\n');
      const found = scanTextForSecrets({ file, text, lineNumbers, commit });
      if (isNewFile) {
        const sensitive = scanSensitiveFile(file, text);
        if (sensitive)
          found.push({ ...sensitive, commit, fingerprint: `${sensitive.fingerprint}:history` });
      }
      for (const f of found) if (!findings.has(f.fingerprint)) findings.set(f.fingerprint, f);
    }
    file = null;
    isNewFile = false;
    lines = [];
    lineNumbers = [];
  };

  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.startsWith('\0commit ')) {
      flush();
      commit = line.slice(8).trim();
    } else if (line.startsWith('diff --git ')) {
      flush();
    } else if (line.startsWith('new file mode')) {
      isNewFile = true;
    } else if (line.startsWith('+++ ')) {
      const target = line.slice(4);
      file = target === '/dev/null' ? null : unquote(target).replace(/^b\//, '');
    } else if (line.startsWith('@@ ')) {
      const m = /\+(\d+)/.exec(line);
      nextLine = m?.[1] ? Number(m[1]) : 0;
    } else if (line.startsWith('+') && file) {
      lines.push(line.slice(1));
      lineNumbers.push(nextLine++);
    }
  }
  flush();

  const code = await exited;
  if (code !== 0) throw new Error(`git log failed: ${stderr.trim() || `exit code ${code}`}`);
  return [...findings.values()];
}

function unquote(p: string): string {
  return p.startsWith('"') && p.endsWith('"') ? p.slice(1, -1).replace(/\\(.)/g, '$1') : p;
}

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { run } from '../../src/cli/program.js';
import { defaultConfig } from '../../src/core/config.js';
import { scan } from '../../src/core/scanner.js';
import { parseSuppressions } from '../../src/core/suppress.js';
import { createFakeSecrets } from '../helpers/fake-secrets.js';
import { materialize, type Materialized } from '../helpers/fixtures.js';

const secrets = createFakeSecrets(99);

describe('parseSuppressions', () => {
  it('applies a trailing comment to its own line', () => {
    expect(parseSuppressions("const k = 'x'; // leakroute-ignore: test key")).toEqual([
      { line: 1, rules: null, reason: 'test key' },
    ]);
  });

  it('applies a comment-only line to the next line, in any comment syntax', () => {
    const content = [
      '// leakroute-ignore: a',
      'x',
      '# leakroute-ignore: b',
      'y',
      '/* leakroute-ignore: c */',
      'z',
      '<!-- leakroute-ignore: d -->',
    ].join('\n');
    expect(parseSuppressions(content).map((s) => [s.line, s.reason])).toEqual([
      [2, 'a'],
      [4, 'b'],
      [6, 'c'],
      [8, 'd'],
    ]);
  });

  it('can be limited to specific rules', () => {
    expect(parseSuppressions('# leakroute-ignore[secret/jwt, endpoint/*]: docs')[0]?.rules).toEqual(
      ['secret/jwt', 'endpoint/*'],
    );
  });

  it('requires a reason', () => {
    expect(parseSuppressions('// leakroute-ignore')).toEqual([]);
    expect(parseSuppressions('// leakroute-ignore:   ')).toEqual([]);
  });
});

describe('scan filters', () => {
  let fx: Materialized | undefined;
  afterEach(() => fx?.cleanup());

  function project(files: Record<string, string>): string {
    fx = materialize('safe/secrets');
    for (const [name, content] of Object.entries(files))
      writeFileSync(path.join(fx.dir, name), content);
    return fx.dir;
  }

  const stripeLine = `export const stripe = '${secrets.__STRIPE__}';`;
  const githubLine = `export const gh = '${secrets.__GITHUB_PAT__}';`;

  it('silences findings marked with leakroute-ignore and counts them', async () => {
    const dir = project({
      'a.ts': `${stripeLine} // leakroute-ignore: revoked test key\n${githubLine}\n`,
    });
    const result = await scan({ root: dir, config: defaultConfig() });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['secret/github-token']);
    expect(result.suppressed).toBe(1);
  });

  it('does not echo the contents of a baseline file that is not JSON', async () => {
    const dir = project({ 'not-json.txt': 'PRIVATE=hunter2-do-not-print\n' });
    const config = { ...defaultConfig(), baseline: 'not-json.txt' };
    await expect(scan({ root: dir, config })).rejects.toThrow(/not valid JSON$/);
    await expect(scan({ root: dir, config })).rejects.not.toThrow(/PRIVATE|hunter2/);
  });

  it('only silences the listed rules', async () => {
    const dir = project({
      'a.ts': `// leakroute-ignore[secret/jwt]: wrong rule\n${stripeLine}\n`,
    });
    const result = await scan({ root: dir, config: defaultConfig() });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['secret/stripe-live-key']);
  });

  it('silences endpoint findings from the line above a route', async () => {
    const dir = project({
      'server.ts': [
        "import express from 'express';",
        'const app = express();',
        '// leakroute-ignore: public product catalogue',
        "app.get('/api/products', (_req, res) => res.json([]));",
        "app.get('/api/orders', (_req, res) => res.json([]));",
      ].join('\n'),
      'api.py': [
        'from flask import Flask',
        'app = Flask(__name__)',
        '# leakroute-ignore[endpoint/flask-*]: status page for the load balancer',
        '@app.get("/api/state")',
        'def state():',
        '    return {}',
      ].join('\n'),
    });
    const result = await scan({ root: dir, config: defaultConfig() });
    expect(result.findings.map((f) => f.title)).toEqual([
      'Possible unprotected endpoint: GET /api/orders',
    ]);
    expect(result.suppressed).toBe(2);
  });

  it('drops disabled rules', async () => {
    const dir = project({ 'a.ts': `${stripeLine}\n${githubLine}\n` });
    const config = { ...defaultConfig(), disableRules: ['secret/github-*'] };
    const result = await scan({ root: dir, config });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['secret/stripe-live-key']);
  });

  it('reports only new findings once a baseline exists', async () => {
    const dir = project({ 'a.ts': `${stripeLine}\n` });
    const io = { stdout: () => undefined, stderr: () => undefined, color: false };
    expect(await run(['baseline', dir], io)).toBe(0);

    const baseline = readFileSync(path.join(dir, '.leakroute-baseline.json'), 'utf8');
    expect(baseline).toContain('secret/stripe-live-key');
    expect(baseline).not.toContain(secrets.__STRIPE__);
    expect(baseline).not.toContain('"line"');

    // Unrelated edits move the secret down; it is still recognised.
    writeFileSync(path.join(dir, 'a.ts'), `// header\n\n${stripeLine}\n${githubLine}\n`);
    const result = await scan({ root: dir, config: defaultConfig() });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['secret/github-token']);
    expect(result.baselined).toBe(1);

    const all = await scan({ root: dir, config: { ...defaultConfig(), baseline: null } });
    expect(all.findings).toHaveLength(2);
  });

  it('regenerating an unchanged baseline produces identical output', async () => {
    const dir = project({ 'a.ts': `${stripeLine}\n${githubLine}\n` });
    const io = { stdout: () => undefined, stderr: () => undefined, color: false };
    await run(['baseline', dir], io);
    const first = readFileSync(path.join(dir, '.leakroute-baseline.json'), 'utf8');
    await run(['baseline', dir], io);
    expect(readFileSync(path.join(dir, '.leakroute-baseline.json'), 'utf8')).toBe(first);
  });

  it('rejects a corrupted baseline with a clear message', async () => {
    const dir = project({ '.leakroute-baseline.json': '{"tool":"other"}' });
    let stderr = '';
    const code = await run(['scan', dir], {
      stdout: () => undefined,
      stderr: (t) => (stderr += t),
      color: false,
    });
    expect(code).toBe(2);
    expect(stderr).toContain('Invalid baseline');
  });

  it('--no-baseline reports everything', async () => {
    const dir = project({ 'a.ts': `${stripeLine}\n` });
    const io = { stdout: () => undefined, stderr: () => undefined, color: false };
    await run(['baseline', dir], io);
    expect(await run(['scan', dir], io)).toBe(0);
    expect(await run(['scan', dir, '--no-baseline'], io)).toBe(1);
  });
});

describe('init', () => {
  it('writes a valid config once', async () => {
    const fx = materialize('safe/secrets');
    try {
      const io = { stdout: () => undefined, stderr: () => undefined, color: false };
      expect(await run(['init', fx.dir], io)).toBe(0);
      expect(await run(['init', fx.dir], io)).toBe(2);
      expect(await run(['scan', fx.dir], io)).toBe(0);
    } finally {
      fx.cleanup();
    }
  });
});

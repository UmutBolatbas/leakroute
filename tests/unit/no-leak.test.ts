import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultConfig } from '../../src/core/config.js';
import { scan } from '../../src/core/scanner.js';
import type { ScanResult } from '../../src/core/types.js';
import { renderJson } from '../../src/reporters/json.js';
import { renderPrComment } from '../../src/reporters/pr-comment.js';
import { renderSarif } from '../../src/reporters/sarif.js';
import { renderSummary } from '../../src/reporters/summary.js';
import { renderTerminal } from '../../src/reporters/terminal.js';
import { materialize, type Materialized } from '../helpers/fixtures.js';

/**
 * The most important guarantee of the tool: a detected secret never appears in
 * any output. Every reporter is checked against every generated secret.
 */
describe('secret values never reach any output', () => {
  let fx: Materialized;
  let result: ScanResult;

  beforeAll(async () => {
    fx = materialize('vulnerable/secrets', { 'env.tmpl': '.env' });
    result = await scan({ root: fx.dir, config: defaultConfig() });
  });
  afterAll(() => fx.cleanup());

  const outputs = () => ({
    json: renderJson(result),
    terminal: renderTerminal(result, { color: false }),
    terminalColor: renderTerminal(result, { color: true }),
    sarif: renderSarif(result),
    summary: renderSummary(result),
    prComment: renderPrComment({ findings: result.findings, otherCount: 0 }),
  });

  it('finds secrets in the first place', () => {
    expect(result.findings.length).toBeGreaterThan(15);
  });

  it.each(['json', 'terminal', 'terminalColor', 'sarif', 'summary', 'prComment'] as const)(
    '%s output contains no secret',
    (name) => {
      const text = outputs()[name];
      for (const [token, value] of Object.entries(fx.secrets)) {
        // Check the full value and a long slice of it: 8+ chars of a secret is already a leak.
        const probe = value.replace(/^-----BEGIN [A-Z ]+-----\\?n?/, '').slice(4, 16);
        expect(text, `${token} leaked in ${name}`).not.toContain(value);
        expect(text, `${token} partially leaked in ${name}`).not.toContain(probe);
      }
    },
  );

  it('shows at most the first 4 characters', () => {
    for (const f of result.findings) {
      if (f.redactedValue) expect(f.redactedValue).toMatch(/^.{0,4}\*{4}$/);
    }
  });
});

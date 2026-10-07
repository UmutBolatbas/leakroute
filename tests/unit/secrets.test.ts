import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding } from '../../src/core/types.js';
import { expectedMarkers, materialize, scanDir, type Materialized } from '../helpers/fixtures.js';

const key = (f: Finding) => `${f.ruleId}@${f.line}`;

describe('secret detection: vulnerable fixtures', () => {
  let fx: Materialized;
  let findings: Finding[];

  beforeAll(async () => {
    fx = materialize('vulnerable/secrets', { 'env.tmpl': '.env' });
    findings = await scanDir(fx.dir);
  });
  afterAll(() => fx.cleanup());

  it.each(['config.ts', 'aws_settings.py', 'settings.yml', '.env'])(
    'reports exactly the marked lines in %s',
    (file) => {
      const actual = findings
        .filter((f) => f.file === file)
        .map(key)
        .sort();
      expect(actual).toEqual(expectedMarkers(fx.dir, file).sort());
    },
  );

  it('reports a private key file by its content, once', () => {
    expect(findings.filter((f) => f.file === 'deploy/id_rsa').map(key)).toEqual([
      'secret/private-key@1',
    ]);
  });

  it('reports a service account file and the escaped key inside it', () => {
    expect(
      findings
        .filter((f) => f.file === 'service-account.json')
        .map(key)
        .sort(),
    ).toEqual(['secret/credentials-file@1', 'secret/private-key@4']);
  });

  it('marks known provider keys as high severity', () => {
    const openai = findings.find((f) => f.ruleId === 'secret/openai-api-key');
    expect(openai?.severity).toBe('high');
  });

  it('gives every finding an explanation and a fix', () => {
    for (const f of findings) {
      expect(f.title).toMatch(/^Possible /);
      expect(f.reason.length).toBeGreaterThan(20);
      expect(f.remediation.length).toBeGreaterThan(10);
    }
  });

  it('produces unique fingerprints', () => {
    const prints = findings.map((f) => f.fingerprint);
    expect(new Set(prints).size).toBe(prints.length);
  });
});

describe('secret detection: safe fixtures', () => {
  it('reports nothing for placeholders, env lookups, public keys and test dummies', async () => {
    const fx = materialize('safe/secrets', { 'env.example': '.env.example' });
    try {
      const findings = await scanDir(fx.dir);
      expect(findings.map((f) => `${f.file}:${key(f)} ${f.redactedValue ?? ''}`)).toEqual([]);
    } finally {
      fx.cleanup();
    }
  });
});

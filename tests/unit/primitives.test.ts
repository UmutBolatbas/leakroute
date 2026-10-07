import { describe, expect, it } from 'vitest';
import { redact } from '../../src/core/redact.js';
import { exceedsThreshold } from '../../src/core/severity.js';
import type { Finding, Severity } from '../../src/core/types.js';
import { findEntropyCandidates, shannonEntropy } from '../../src/rules/secrets/entropy.js';
import { isPlaceholder, isTestLikePath } from '../../src/rules/secrets/placeholder.js';
import { scanSensitiveFile } from '../../src/rules/secrets/index.js';

describe('redact', () => {
  it('keeps the first 4 characters and a fixed-length mask', () => {
    expect(redact('sk-abcdefghijklmnop')).toBe('sk-a****');
    expect(redact('a'.repeat(200))).toBe('aaaa****');
  });

  it('hides short values entirely', () => {
    expect(redact('hunter2')).toBe('****');
    expect(redact('')).toBe('****');
  });
});

describe('shannonEntropy', () => {
  it('is 0 for a repeated character and grows with variety', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('ab')).toBe(1);
    expect(shannonEntropy('q8Zr2LmN4pX7vB1kT9wY3cF6')).toBeGreaterThan(4);
  });
});

describe('entropy candidates', () => {
  const names = (text: string, file = 'src/app.ts') =>
    findEntropyCandidates(file, text).map((c) => c.name);

  it('only looks at credential-like names', () => {
    expect(names(`const clientSecret = "q8Zr2LmN4pX7vB1kT9wY3cF6";`)).toEqual(['clientSecret']);
    expect(names(`const buildHash = "q8Zr2LmN4pX7vB1kT9wY3cF6";`)).toEqual([]);
  });

  it('ignores benign names that contain a sensitive word', () => {
    expect(names(`const tokenizer = "q8Zr2LmN4pX7vB1kT9wY3cF6";`)).toEqual([]);
    expect(names(`const publishableKey = "q8Zr2LmN4pX7vB1kT9wY3cF6";`)).toEqual([]);
    expect(names(`const keyId = "q8Zr2LmN4pX7vB1kT9wY3cF6";`)).toEqual([]);
  });

  it('reads unquoted values only in config-style files', () => {
    expect(names('API_TOKEN=q8Zr2LmN4pX7vB1kT9wY3cF6', '.env')).toEqual(['API_TOKEN']);
    expect(names('API_TOKEN=q8Zr2LmN4pX7vB1kT9wY3cF6', 'src/app.ts')).toEqual([]);
  });

  it('skips low-entropy values', () => {
    expect(names(`const apiKey = "aaaaaaaaaaaaaaaaaaaa";`)).toEqual([]);
    expect(names(`const authToken = "abcdefgh12345678";`)).toEqual(['authToken']);
  });
});

describe('placeholders', () => {
  it.each([
    'your-api-key-here',
    'AKIAIOSFODNN7EXAMPLE',
    'sk-xxxxxxxxxxxxxxxxxxxx',
    '${API_KEY}',
    '{{ secrets.TOKEN }}',
    '<YOUR_TOKEN>',
    'changeme',
    '1234567890abcdef',
    '00000000000000000000',
  ])('treats %s as a placeholder', (value) => {
    expect(isPlaceholder(value)).toBe(true);
  });

  it('treats test-ish values as fake only in test paths', () => {
    expect(isPlaceholder('q8Zr2Lmtest4pX7', 'tests/auth.test.ts')).toBe(true);
    expect(isPlaceholder('q8Zr2Lmtest4pX7', 'src/auth.ts')).toBe(false);
  });

  it.each(['tests/a.ts', 'src/__tests__/a.ts', 'src/a.spec.ts', 'test_api.py', 'examples/demo.js'])(
    '%s is a test-like path',
    (p) => expect(isTestLikePath(p)).toBe(true),
  );
  it.each(['src/latest.ts', 'src/contest/app.ts'])('%s is not a test-like path', (p) =>
    expect(isTestLikePath(p)).toBe(false),
  );
});

describe('sensitive files', () => {
  const rule = (file: string, content: string | null = 'X=1') =>
    scanSensitiveFile(file, content)?.ruleId;

  it('flags committed credential files', () => {
    expect(rule('.env', 'TOKEN=abc123')).toBe('secret/env-file');
    expect(rule('config/.env.production', 'TOKEN=abc123')).toBe('secret/env-file');
    expect(rule('keys/cert.p12', null)).toBe('secret/private-key-file');
    expect(rule('credentials.json', '{"a":1}')).toBe('secret/credentials-file');
    expect(rule('infra/terraform.tfstate', '{}')).toBe('secret/credentials-file');
    expect(rule('.npmrc', '//registry.npmjs.org/:_authToken=abc123')).toBe(
      'secret/credentials-file',
    );
  });

  it('ignores templates, public keys and harmless configs', () => {
    expect(rule('.env.example', 'TOKEN=abc123')).toBeUndefined();
    expect(rule('.env', 'TOKEN=\nOTHER=')).toBeUndefined();
    expect(rule('id_ed25519.pub', 'ssh-ed25519 AAAA')).toBeUndefined();
    expect(
      rule('cert.pem', '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'),
    ).toBeUndefined();
    expect(rule('.npmrc', '//registry.npmjs.org/:_authToken=${NPM_TOKEN}')).toBeUndefined();
  });
});

describe('fail-on threshold', () => {
  const at = (severity: Severity) => [{ severity } as Finding];

  it('compares against the threshold', () => {
    expect(exceedsThreshold(at('high'), 'high')).toBe(true);
    expect(exceedsThreshold(at('medium'), 'high')).toBe(false);
    expect(exceedsThreshold(at('medium'), 'medium')).toBe(true);
    expect(exceedsThreshold(at('low'), 'low')).toBe(true);
    expect(exceedsThreshold(at('high'), 'none')).toBe(false);
    expect(exceedsThreshold([], 'low')).toBe(false);
  });
});

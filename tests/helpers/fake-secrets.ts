/**
 * Generates realistic-looking but fake credentials at test time.
 *
 * Nothing in the repository contains a complete token in a provider's format:
 * prefixes are split ('sk' + '-proj-') so GitHub push protection and our own
 * self-scan never see one. The generator is seeded, so test runs are reproducible.
 */

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const ALNUM = UPPER + LOWER + DIGITS;

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function createFakeSecrets(seed = 1337) {
  const rand = mulberry32(seed);
  const pick = (length: number, alphabet = ALNUM) =>
    Array.from({ length }, () => alphabet[Math.floor(rand() * alphabet.length)]).join('');
  const b64url = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');

  const keyBody = Array.from({ length: 6 }, () => pick(64, ALNUM + '+/')).join('\n');

  return {
    __ANTHROPIC__: 'sk' + '-ant-' + 'api03-' + pick(93, ALNUM + '-_') + 'AA',
    __OPENAI__: 'sk' + '-proj-' + pick(64, ALNUM + '-_'),
    __OPENAI_LEGACY__: 'sk' + '-' + pick(20) + 'T3Blbk' + 'FJ' + pick(20),
    __AWS_KEY_ID__: 'AK' + 'IA' + pick(16, UPPER + DIGITS),
    __AWS_SECRET__: pick(40, ALNUM + '/+'),
    __GITHUB_PAT__: 'gh' + 'p_' + pick(36),
    __GITHUB_FINE__: 'github' + '_pat_' + pick(22) + '_' + pick(59),
    __STRIPE__: 'sk' + '_live_' + pick(24),
    __SLACK__: 'xo' + 'xb-' + pick(12, DIGITS) + '-' + pick(13, DIGITS) + '-' + pick(24),
    __SLACK_WEBHOOK__:
      'https://hooks.slack' +
      '.com/services/T' +
      pick(8, UPPER + DIGITS) +
      '/B' +
      pick(10, UPPER + DIGITS) +
      '/' +
      pick(24),
    __GOOGLE__: 'AI' + 'za' + pick(35, ALNUM + '-_'),
    __NPM__: 'np' + 'm_' + pick(36),
    __SENDGRID__: 'S' + 'G.' + pick(22) + '.' + pick(43),
    __HUGGINGFACE__: 'h' + 'f_' + pick(34, UPPER + LOWER),
    __JWT__:
      b64url({ alg: 'HS256', typ: 'JWT' }) +
      '.' +
      b64url({ sub: '42', iat: 1700000000 }) +
      '.' +
      pick(43, ALNUM + '-_'),
    __PRIVATE_KEY__:
      '-----BEGIN ' + 'RSA PRIVATE KEY-----\n' + keyBody + '\n-----END ' + 'RSA PRIVATE KEY-----',
    // As it appears inside a JSON string, e.g. a GCP service account file.
    __PRIVATE_KEY_ESCAPED__:
      '-----BEGIN ' +
      'PRIVATE KEY-----\\n' +
      keyBody.replace(/\n/g, '\\n') +
      '\\n-----END ' +
      'PRIVATE KEY-----\\n',
    __DB_PASSWORD__: pick(20),
    __GENERIC__: pick(32),
    __HEX__: pick(40, DIGITS + 'abcdef'),
    __PASSWORD__: pick(6, LOWER) + pick(3, DIGITS) + '!' + pick(2, UPPER),
  };
}

export type FakeSecrets = ReturnType<typeof createFakeSecrets>;

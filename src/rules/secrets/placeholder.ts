/**
 * Heuristics for values that look like secrets but are obviously fake:
 * documentation samples, template placeholders and test dummies.
 */

const PLACEHOLDER_WORDS =
  /example|sample|placeholder|dummy|fake|changeme|change[-_]me|redacted|replace[-_]?me|your[-_ ]|_here\b|-here\b|insert[-_]|x{4,}/i;

/** Extra words that only count as "fake" inside test/fixture/example files. */
const TEST_ONLY_WORDS = /test|mock|stub|fixture/i;

const TEMPLATE_SYNTAX = /\$\{|\{\{|\}\}|<[^>]*>|%\(|%s|\$[A-Z_]{3,}/;

const TEST_PATH =
  /(^|\/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|__mocks__|mocks?|examples?|samples?|testdata|docs?)(\/|$)|\.(test|spec)\.[a-z]+$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$/i;

export function isTestLikePath(file: string): boolean {
  return TEST_PATH.test(file);
}

export function isPlaceholder(value: string, file?: string): boolean {
  if (PLACEHOLDER_WORDS.test(value)) return true;
  if (TEMPLATE_SYNTAX.test(value)) return true;
  if (/\*{3,}|\.{3,}|•{3,}/.test(value)) return true;
  // Long runs of the same character: "aaaaaaaa", "00000000".
  if (/(.)\1{7,}/.test(value)) return true;
  if (isSequential(value)) return true;
  if (file && isTestLikePath(file) && TEST_ONLY_WORDS.test(value)) return true;
  return false;
}

const SEQUENCES = [
  '0123456789abcdefghijklmnopqrstuvwxyz',
  '1234567890abcdefghijklmnopqrstuvwxyz',
  'zyxwvutsrqponmlkjihgfedcba9876543210',
];

/** Values like "1234567890abcdef" or "abcdefghijklmnop". */
function isSequential(value: string): boolean {
  const core = value.replace(/^[a-z]+[-_]/i, '');
  if (core.length < 8) return false;
  const lower = core.toLowerCase();
  return SEQUENCES.some((seq) => seq.includes(lower));
}

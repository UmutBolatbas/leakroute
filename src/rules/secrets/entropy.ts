import type { Severity } from '../../core/types.js';

/**
 * Generic secret detection: high-entropy literals assigned to variables whose name
 * says "secret". Restricting it to suspicious names keeps false positives low:
 * random-looking strings are everywhere (hashes, IDs, base64 assets), but random
 * strings assigned to `apiKey` usually are credentials.
 */

/** `apiKey = "..."`, `"client_secret": "..."`, `token: '...'`, `if (pwd === "...")` */
const QUOTED_ASSIGNMENT =
  /(?<name>[A-Za-z_$][\w$.-]*)["']?[ \t]*(?:===?|!==?|:=|=>|:|=)[ \t]*(?:[rbuf]{0,2})(?<q>["'`])(?<secret>[^"'`\s]{8,256})\k<q>/dg;

/** `API_KEY=abc123` in .env / shell / ini files, `api_key: abc123` in YAML. */
const UNQUOTED_ASSIGNMENT =
  /^[ \t]*(?:export[ \t]+|ENV[ \t]+|-[ \t]+)?(?<name>[A-Za-z_][\w.-]*)[ \t]*[:=][ \t]*(?<secret>[^\s'"`#]{8,256})[ \t]*(?:#.*)?$/dgm;

const UNQUOTED_FILE =
  /(?:^|\/)(?:\.env(?:\.[\w.-]+)?|[^/]+\.(?:env|ini|cfg|conf|properties|ya?ml|sh|bash|zsh)|Dockerfile[^/]*)$/i;

const SENSITIVE_NAME = /key|secret|token|passw(?:or)?d|pwd|credential|auth|private/i;
const PASSWORD_NAME = /passw(?:or)?d|pwd/i;

/** Names that contain a sensitive word but don't hold secrets. */
const BENIGN_NAME =
  /(?:public|publishable|pub|anon)[_-]?key|key(?:s|word|board|name|id|path|file|type|code|len|length|size|prefix|field|column|map|ring)\b|tokens?(?:izer|type|count|limit|endpoint|url|uri|name|ize|s)\b|author|authority|auth(?:enticate|orize|url|uri|endpoint|domain|provider|mode|type|method|header|scheme|strategy|state|status|required)|(?:primary|foreign|sort|cache|partition|idempotency|storage|query|route|i18n|translation|react)[_-]?key|(?:url|uri|path|file|name|id|label|placeholder|hint|title|message|field|input|length|policy|type|count|ttl|expiry|expires|header)$/i;

export interface EntropyCandidate {
  name: string;
  value: string;
  /** Offset of the value inside the scanned text. */
  index: number;
  ruleId: 'secret/hardcoded-password' | 'secret/generic-high-entropy';
  severity: Severity;
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function findEntropyCandidates(file: string, text: string): EntropyCandidate[] {
  const out: EntropyCandidate[] = [];
  const regexes = UNQUOTED_FILE.test(file)
    ? [QUOTED_ASSIGNMENT, UNQUOTED_ASSIGNMENT]
    : [QUOTED_ASSIGNMENT];

  for (const regex of regexes) {
    for (const match of text.matchAll(regex)) {
      const name = match.groups?.name ?? '';
      const value = match.groups?.secret ?? '';
      const index = match.indices?.groups?.secret?.[0];
      if (index === undefined) continue;

      const verdict = classify(name, value);
      if (verdict) out.push({ name, value, index, ...verdict });
    }
  }
  return out;
}

function classify(
  name: string,
  value: string,
): Omit<EntropyCandidate, 'name' | 'value' | 'index'> | null {
  // Only look at the last segment: `config.auth.clientSecret` -> `clientSecret`.
  const leaf = name.split('.').pop() ?? name;
  if (!SENSITIVE_NAME.test(leaf) || BENIGN_NAME.test(leaf)) return null;
  if (looksLikeNonSecret(value, leaf)) return null;

  const entropy = shannonEntropy(value);

  if (PASSWORD_NAME.test(leaf)) {
    // Passwords are often human-chosen, so a lower bar, but still not a plain word.
    if (value.length >= 8 && entropy >= 2.5 && /[^A-Za-z]/.test(value)) {
      return { ruleId: 'secret/hardcoded-password', severity: 'medium' };
    }
    return null;
  }

  const isHex = /^[0-9a-f]+$/i.test(value);
  const strongEnough = isHex
    ? value.length >= 20 && entropy >= 3.0
    : value.length >= 16 && entropy >= 3.5 && /\d/.test(value) && /[A-Za-z]/.test(value);
  return strongEnough ? { ruleId: 'secret/generic-high-entropy', severity: 'medium' } : null;
}

function looksLikeNonSecret(value: string, name: string): boolean {
  if (value.toLowerCase() === name.toLowerCase()) return true;
  if (/^(?:https?|wss?|file):\/\//i.test(value) && !/:[^/@]+@/.test(value)) return true;
  if (/^(?:\.{0,2}\/|~\/|[A-Za-z]:\\)/.test(value)) return true;
  if (/^[A-Za-z]+(?:[._:-][A-Za-z]+)+$/.test(value)) return true; // i18n keys, header names, kebab ids
  if (/^(?:true|false|null|none|undefined)$/i.test(value)) return true;
  if (/^(?:process\.env|os\.environ|import\.meta\.env|env\(|getenv)/i.test(value)) return true;
  if (/^[\w-]+\.(?:js|ts|json|ya?ml|pem|key|crt|txt|env)$/i.test(value)) return true;
  // Version strings, semver ranges, dates
  if (/^[v^~>=<]*\d+(?:\.\d+)+(?:[-+][\w.]+)?$/.test(value)) return true;
  return false;
}

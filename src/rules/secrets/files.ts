import type { Severity } from '../../core/types.js';
import { isPlaceholder } from './placeholder.js';

/**
 * Files whose mere presence in a repository is a problem, regardless of which
 * individual strings inside them match a pattern.
 */
export interface SensitiveFileRule {
  id: string;
  title: string;
  severity: Severity;
  /** Matched against the basename. */
  name: RegExp;
  remediation: string;
  /**
   * Optional content check. `content` is `null` when the file is binary or too large.
   * Return `false` to skip the file.
   */
  check?: (content: string | null) => boolean;
}

const REMOVE =
  'Delete the file, add it to .gitignore and rotate every credential it contained. Deleting it in a new commit does not remove it from git history.';

export const SENSITIVE_FILE_RULES: readonly SensitiveFileRule[] = [
  {
    id: 'secret/env-file',
    title: 'Committed .env file',
    severity: 'high',
    name: /^(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$/i,
    remediation: `${REMOVE} Commit a .env.example with empty values instead.`,
    check: (content) => {
      if (content === null) return true;
      return content.split(/\r?\n/).some((line) => {
        const m = /^\s*(?:export\s+)?[A-Za-z_][\w.]*\s*=\s*["']?([^\s"'#]+)/.exec(line);
        return m?.[1] !== undefined && !isPlaceholder(m[1]);
      });
    },
  },
  {
    id: 'secret/private-key-file',
    title: 'Committed private key file',
    severity: 'high',
    name: /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|key|ppk|p12|pfx|jks|keystore|kdbx))$/i,
    remediation: REMOVE,
    // PEM files with a private key block are already reported (with a line number)
    // by the private-key pattern, and certificate-only PEMs are public.
    check: (content) => {
      if (content === null) return true;
      if (/PRIVATE KEY-----/.test(content)) return false;
      if (/-----BEGIN (?:CERTIFICATE|PUBLIC KEY|X509 CRL|CERTIFICATE REQUEST)/.test(content)) {
        return false;
      }
      return /PuTTY-User-Key-File|Private-Lines/.test(content) || content.trim().length > 0;
    },
  },
  {
    id: 'secret/credentials-file',
    title: 'Committed credentials file',
    severity: 'high',
    name: /^(?:credentials\.json|client_secrets?(?:[\w.-]*)\.json|service[-_]?account[\w.-]*\.json|\.git-credentials|\.netrc|_netrc|\.pgpass|\.pypirc|terraform\.tfstate(?:\.backup)?)$/i,
    remediation: REMOVE,
    check: (content) => content === null || content.trim().length > 0,
  },
  {
    id: 'secret/credentials-file',
    title: 'npm config with an auth token',
    severity: 'high',
    name: /^\.npmrc$/i,
    remediation: `${REMOVE} Use \${NPM_TOKEN} in .npmrc and provide the token from CI secrets.`,
    check: (content) =>
      content !== null && /(?:_authToken|_auth|_password)\s*=\s*(?!\$\{)[^\s]+/.test(content),
  },
  {
    id: 'secret/credentials-file',
    title: 'Committed .htpasswd file',
    severity: 'medium',
    name: /^\.htpasswd$/i,
    remediation:
      'Password hashes can be cracked offline. Remove the file and reset these passwords.',
  },
];

const ENV_TEMPLATE = /\.(?:example|sample|template|tpl|dist|defaults|schema)$/i;

export function matchSensitiveFile(basename: string): SensitiveFileRule | undefined {
  if (ENV_TEMPLATE.test(basename)) return undefined;
  if (basename.endsWith('.pub')) return undefined;
  return SENSITIVE_FILE_RULES.find((rule) => rule.name.test(basename));
}

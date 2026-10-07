import type { Severity } from '../../core/types.js';

/**
 * Known credential formats.
 *
 * Every regex here was written from the providers' public token format documentation.
 * None are copied from other scanners. Each regex must have a named `secret` group
 * (the part that gets redacted and placeholder-checked) and the `d` flag so we can
 * report the exact column.
 *
 * Order matters: when two patterns match overlapping text, the earlier one wins,
 * so more specific formats come first.
 */
export interface SecretPattern {
  id: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  remediation: string;
  /**
   * Optional extra validation. Return `false` to drop the match, or a severity to
   * override the default one.
   */
  check?: (secret: string, groups: Record<string, string | undefined>) => boolean | Severity;
}

const ROTATE =
  'Revoke/rotate this credential now, then load it from an environment variable or a secret manager.';

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'secret/private-key',
    title: 'Private key block',
    severity: 'high',
    // The lookahead requires actual key material after the header, so docs that only
    // mention "-----BEGIN PRIVATE KEY-----" don't match. Handles JSON-escaped "\n" too.
    regex:
      /-----BEGIN (?<secret>(?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----(?=(?:\\[rn]|\s)*(?:[A-Za-z-]+:[^\n]*(?:\\n|\n)(?:\\[rn]|\s)*)*[A-Za-z0-9+/]{32})/dg,
    remediation: `Remove the key from the repository and generate a new key pair. ${ROTATE}`,
  },
  {
    id: 'secret/anthropic-api-key',
    title: 'Anthropic API key',
    severity: 'high',
    regex: /\b(?<secret>sk-ant-(?:api|admin|oat|sid)\d{2}-[A-Za-z0-9_-]{32,})/dg,
    remediation: `Revoke the key in the Anthropic Console. ${ROTATE}`,
  },
  {
    id: 'secret/openai-api-key',
    title: 'OpenAI API key',
    severity: 'high',
    regex:
      /\b(?<secret>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{48})(?![A-Za-z0-9_-])/dg,
    remediation: `Revoke the key in the OpenAI dashboard. ${ROTATE}`,
  },
  {
    id: 'secret/aws-access-key-id',
    title: 'AWS access key ID',
    severity: 'high',
    regex: /\b(?<secret>(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16})\b/dg,
    remediation: `Deactivate the access key in AWS IAM and prefer IAM roles / OIDC over long-lived keys. ${ROTATE}`,
  },
  {
    id: 'secret/aws-secret-access-key',
    title: 'AWS secret access key',
    severity: 'high',
    regex:
      /aws[\w.-]{0,20}?secret[\w.-]{0,20}?["']?\s*(?::=|=>|:|=)\s*["']?(?<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/dgi,
    remediation: `Deactivate the access key in AWS IAM. ${ROTATE}`,
  },
  {
    id: 'secret/github-token',
    title: 'GitHub token',
    severity: 'high',
    regex:
      /\b(?<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{50,})\b/dg,
    remediation: `Revoke the token under GitHub Settings > Developer settings. In Actions, use the built-in GITHUB_TOKEN or repository secrets. ${ROTATE}`,
  },
  {
    id: 'secret/stripe-live-key',
    title: 'Stripe live secret key',
    severity: 'high',
    regex: /\b(?<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})\b/dg,
    remediation: `Roll the key in the Stripe dashboard. ${ROTATE}`,
  },
  {
    id: 'secret/slack-token',
    title: 'Slack token',
    severity: 'high',
    regex: /\b(?<secret>xox[abposre]-[0-9A-Za-z-]{10,}|xapp-\d-[0-9A-Za-z-]{10,})/dg,
    remediation: `Revoke the token in your Slack app settings. ${ROTATE}`,
  },
  {
    id: 'secret/slack-webhook',
    title: 'Slack incoming webhook URL',
    severity: 'medium',
    regex:
      /(?<secret>https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]{20,})/dg,
    remediation: `Anyone with this URL can post to your channel. Regenerate the webhook. ${ROTATE}`,
  },
  {
    id: 'secret/google-api-key',
    title: 'Google API key',
    severity: 'medium',
    regex: /\b(?<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/dg,
    remediation:
      'If this key is meant to be public (e.g. Maps in a browser), restrict it by HTTP referrer and API in Google Cloud Console. Otherwise rotate it and move it server-side.',
  },
  {
    id: 'secret/npm-token',
    title: 'npm access token',
    severity: 'high',
    regex: /\b(?<secret>npm_[A-Za-z0-9]{36})\b/dg,
    remediation: `Revoke the token on npmjs.com. In CI, use trusted publishing or a repository secret. ${ROTATE}`,
  },
  {
    id: 'secret/sendgrid-api-key',
    title: 'SendGrid API key',
    severity: 'high',
    regex: /\b(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/dg,
    remediation: `Delete the key in SendGrid settings. ${ROTATE}`,
  },
  {
    id: 'secret/huggingface-token',
    title: 'Hugging Face access token',
    severity: 'high',
    regex: /\b(?<secret>hf_[A-Za-z]{34})\b/dg,
    remediation: `Invalidate the token in your Hugging Face settings. ${ROTATE}`,
  },
  {
    id: 'secret/jwt',
    title: 'JSON Web Token',
    severity: 'medium',
    regex:
      /\b(?<secret>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/dg,
    remediation:
      'A hardcoded JWT may grant access until it expires. Remove it, and if it was signed with a production key, rotate that signing key.',
    check: (secret) => looksLikeJwtHeader(secret.slice(0, secret.indexOf('.'))),
  },
  {
    id: 'secret/database-url',
    title: 'Database connection string with password',
    severity: 'high',
    regex:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^\s:@/'"`]+:(?<secret>[^\s@/'"`]+)@(?<host>[^\s/'"`:?,;)]+)/dg,
    remediation: `Change the database password and read the connection string from an environment variable. ${ROTATE}`,
    check: (secret, groups) => {
      const local = LOCAL_HOST.test(groups.host ?? '');
      const weak = DEFAULT_PASSWORD.test(secret);
      // `postgres://user:password@localhost` is a tutorial value, not a leak.
      if (local && weak) return false;
      return local || weak ? 'low' : true;
    },
  },
];

/** Passwords that appear in tutorials and docker-compose files rather than real deployments. */
const DEFAULT_PASSWORD = /^(?:pass(?:word|wd)?|pw|secret|postgres|root|admin|mysql|guest|test)$/i;

/** Hosts that point at a developer machine or a docker-compose service, not production. */
const LOCAL_HOST =
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)$/i;

function looksLikeJwtHeader(part: string): boolean {
  try {
    const header: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return typeof header === 'object' && header !== null && 'alg' in header;
  } catch {
    return false;
  }
}

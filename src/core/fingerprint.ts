import { createHash } from 'node:crypto';

/**
 * Builds a stable fingerprint from non-sensitive parts.
 *
 * Fingerprints avoid line numbers so a baseline survives unrelated edits.
 * Secret findings must never pass the raw secret (or a hash of it) here:
 * a hash of a weak password can be brute-forced, so callers use the redacted
 * value plus an occurrence index instead.
 */
export function fingerprint(...parts: readonly (string | number)[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 32);
}

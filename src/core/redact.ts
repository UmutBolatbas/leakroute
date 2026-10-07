const MASK = '****';
const VISIBLE_CHARS = 4;
/** Below this length even 4 characters reveal too much of the value. */
const MIN_LENGTH_TO_REVEAL = 12;

/**
 * Masks a secret for display: `sk-abc123...` -> `sk-a****`.
 *
 * This is the only place where a secret value is turned into something printable.
 * The mask has a fixed length so the output doesn't reveal how long the secret is.
 */
export function redact(value: string): string {
  if (value.length < MIN_LENGTH_TO_REVEAL) return MASK;
  return value.slice(0, VISIBLE_CHARS) + MASK;
}

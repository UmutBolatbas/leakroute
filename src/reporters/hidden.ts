import type { ScanResult } from '../core/types.js';

/** "Not shown: 2 silenced by leakroute-ignore, 5 already in the baseline." or `null`. */
export function hiddenNote(result: Pick<ScanResult, 'suppressed' | 'baselined'>): string | null {
  const parts: string[] = [];
  if (result.suppressed > 0)
    parts.push(`${result.suppressed} silenced by leakroute-ignore comments`);
  if (result.baselined > 0) parts.push(`${result.baselined} already in the baseline`);
  return parts.length > 0 ? `Not shown: ${parts.join(', ')}.` : null;
}

import { countBySeverity } from '../core/severity.js';
import type { ScanResult } from '../core/types.js';
import { TOOL_NAME, VERSION } from '../version.js';

export function renderJson(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: { name: TOOL_NAME, version: VERSION },
      summary: {
        filesScanned: result.filesScanned,
        durationMs: result.durationMs,
        total: result.findings.length,
        ...countBySeverity(result.findings),
        suppressed: result.suppressed,
        baselined: result.baselined,
        unparsedFiles: result.unparsedFiles,
      },
      findings: result.findings,
    },
    null,
    2,
  );
}

import type { ScanResult } from '../core/types.js';
import { TOOL_NAME, VERSION } from '../version.js';
import { hiddenNote } from './hidden.js';
import { cell, code, countsLine, inline, location, SEVERITY_BADGE } from './markdown.js';

export interface SummaryOptions {
  /** e.g. `https://github.com/owner/repo/blob/<sha>/` */
  linkBase?: string;
  /** Rows beyond this are summarized, to stay under GitHub's 1 MB summary limit. */
  maxRows?: number;
}

/** Markdown for the GitHub Actions job summary. */
export function renderSummary(result: ScanResult, options: SummaryOptions = {}): string {
  const maxRows = options.maxRows ?? 200;
  const { findings } = result;
  const lines = [`## 🛡️ ${TOOL_NAME}`, ''];

  if (findings.length === 0) {
    lines.push(`✅ No issues found in ${result.filesScanned} files.`);
  } else {
    lines.push(
      `**${findings.length} possible ${findings.length === 1 ? 'issue' : 'issues'}** in ${result.filesScanned} files: ${countsLine(findings)}`,
      '',
      '| Risk | Location | Rule | Description | Suggested fix |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const f of findings.slice(0, maxRows)) {
      const history = f.commit ? ` _(git history, ${f.commit.slice(0, 7)})_` : '';
      lines.push(
        `| ${SEVERITY_BADGE[f.severity]} | ${cell(location(f, options.linkBase))}${history} | ${code(f.ruleId)} | **${cell(inline(f.title))}**. ${cell(inline(f.reason))} | ${cell(inline(f.remediation))} |`,
      );
    }
    if (findings.length > maxRows) {
      lines.push(
        '',
        `…and ${findings.length - maxRows} more. See the SARIF file or Code Scanning for the full list.`,
      );
    }
  }

  const hidden = hiddenNote(result);
  if (hidden) lines.push('', `ℹ️ ${hidden}`);
  if (result.unparsedFiles.length > 0) {
    lines.push(
      '',
      `⚠️ ${result.unparsedFiles.length} file(s) could not be parsed and were skipped by endpoint rules.`,
    );
  }
  lines.push(
    '',
    `<sub>${TOOL_NAME} v${VERSION} · static analysis can be wrong; every finding explains why it was flagged.</sub>`,
  );
  return lines.join('\n');
}

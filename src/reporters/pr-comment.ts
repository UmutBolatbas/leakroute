import type { Finding } from '../core/types.js';
import { TOOL_NAME, VERSION } from '../version.js';
import { cell, code, countsLine, inline, location, SEVERITY_BADGE } from './markdown.js';

/** Hidden marker used to find and update our own comment instead of posting a new one. */
export const PR_COMMENT_MARKER = '<!-- leakroute:pr-comment -->';

/** GitHub rejects comments over 65,536 characters. */
const MAX_LENGTH = 60_000;
const MAX_ROWS = 50;

export interface PrCommentInput {
  /** Findings in files changed by the PR. */
  findings: readonly Finding[];
  /** Findings elsewhere in the repository, only counted. */
  otherCount: number;
  linkBase?: string;
  /** Link to the workflow run, for the full report. */
  runUrl?: string;
}

export function renderPrComment(input: PrCommentInput): string {
  const { findings } = input;
  const out = [PR_COMMENT_MARKER, `## 🛡️ ${TOOL_NAME}`, ''];

  if (findings.length === 0) {
    out.push('✅ No issues found in the files changed by this pull request.');
  } else {
    out.push(
      `Found **${findings.length} possible ${findings.length === 1 ? 'issue' : 'issues'}** in files changed by this pull request: ${countsLine(findings)}`,
      '',
      '| Risk | Location | Issue |',
      '| --- | --- | --- |',
    );
    const shown = findings.slice(0, MAX_ROWS);
    for (const f of shown) {
      out.push(
        `| ${SEVERITY_BADGE[f.severity]} | ${cell(location(f, input.linkBase))} | ${cell(inline(f.title))} |`,
      );
    }
    if (findings.length > shown.length)
      out.push('', `…and ${findings.length - shown.length} more.`);

    out.push('', '<details><summary>Why these were flagged and how to fix them</summary>', '');
    shown.forEach((f, i) => {
      out.push(
        `#### ${i + 1}. ${inline(f.title)} — ${code(`${f.file}:${f.line}`)}`,
        '',
        `**Why:** ${inline(f.reason)}`,
        '',
        `**Fix:** ${inline(f.remediation)}`,
        '',
      );
    });
    out.push('</details>');
  }

  if (input.otherCount > 0) {
    const where = input.runUrl ? `[the job summary](${input.runUrl})` : 'the job summary';
    out.push('', `ℹ️ ${input.otherCount} more in files this PR did not change. See ${where}.`);
  }
  out.push(
    '',
    `<sub>${TOOL_NAME} v${VERSION} · static analysis can be wrong. To silence a line, add \`leakroute-ignore: <reason>\` in a comment on it. This comment is updated on every push.</sub>`,
  );

  let body = out.join('\n');
  if (body.length > MAX_LENGTH) {
    body = `${body.slice(0, MAX_LENGTH)}\n\n…(truncated)</details>`;
  }
  return body;
}

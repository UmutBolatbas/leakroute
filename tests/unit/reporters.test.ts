import { describe, expect, it, vi } from 'vitest';
import type { Finding, ScanResult } from '../../src/core/types.js';
import { upsertPrComment, type Octokit } from '../../src/github/api.js';
import { cell } from '../../src/reporters/markdown.js';
import { PR_COMMENT_MARKER, renderPrComment } from '../../src/reporters/pr-comment.js';
import { renderSarif } from '../../src/reporters/sarif.js';
import { renderSummary } from '../../src/reporters/summary.js';
import { RULES } from '../../src/rules/registry.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'endpoint/express-unprotected-route',
    category: 'endpoint',
    severity: 'high',
    file: 'src/routes/admin users.ts',
    line: 12,
    column: 3,
    title: 'Possible unprotected endpoint: POST /admin',
    reason: 'No auth | found.',
    remediation: 'Add `requireAuth`.',
    fingerprint: 'abc123',
    ...overrides,
  };
}

const result = (findings: Finding[]): ScanResult => ({
  findings,
  filesScanned: 10,
  durationMs: 5,
  unparsedFiles: [],
  suppressed: 0,
  baselined: 0,
});

describe('SARIF', () => {
  const sarif = JSON.parse(
    renderSarif(
      result([
        finding(),
        finding({
          ruleId: 'secret/openai-api-key',
          category: 'secret',
          severity: 'medium',
          redactedValue: 'sk-p****',
          fingerprint: 'def456',
          commit: 'a'.repeat(40),
        }),
      ]),
    ),
  );
  const run = sarif.runs[0];

  it('declares every rule so fixed alerts can close', () => {
    expect(sarif.version).toBe('2.1.0');
    const ids = run.tool.driver.rules.map((r: { id: string }) => r.id);
    for (const id of RULES.keys()) expect(ids).toContain(id);
  });

  it('gives rules a security severity for Code Scanning', () => {
    for (const rule of run.tool.driver.rules) {
      expect(rule.properties['security-severity']).toMatch(/^\d+\.\d$/);
      expect(rule.properties.tags).toContain('security');
    }
  });

  it('maps severity to level and keeps stable fingerprints', () => {
    expect(run.results.map((r: { level: string }) => r.level)).toEqual(['error', 'warning']);
    expect(run.results[0].partialFingerprints).toEqual({ 'leakroute/v1': 'abc123' });
  });

  it('encodes file paths as URIs relative to the source root', () => {
    const location = run.results[0].locations[0].physicalLocation;
    expect(location.artifactLocation).toEqual({
      uri: 'src/routes/admin%20users.ts',
      uriBaseId: '%SRCROOT%',
    });
    expect(location.region).toEqual({ startLine: 12, startColumn: 3 });
  });

  it('mentions git history in the message', () => {
    expect(run.results[1].message.text).toContain('found in git history');
  });

  it('points each result at its rule', () => {
    for (const r of run.results) expect(run.tool.driver.rules[r.ruleIndex].id).toBe(r.ruleId);
  });
});

describe('markdown', () => {
  it('escapes table cells', () => {
    expect(cell('a | b\nc')).toBe('a \\| b c');
  });

  it('renders a job summary with links', () => {
    const md = renderSummary(result([finding()]), { linkBase: 'https://github.com/o/r/blob/sha/' });
    expect(md).toContain('| Risk | Location | Rule | Description | Suggested fix |');
    expect(md).toContain('(https://github.com/o/r/blob/sha/src/routes/admin%20users.ts#L12)');
    expect(md).toContain('No auth \\| found.');
  });

  it('says so when there is nothing to report', () => {
    expect(renderSummary(result([]))).toContain('No issues found in 10 files');
  });

  it('caps the summary length', () => {
    const many = Array.from({ length: 250 }, (_, i) =>
      finding({ line: i + 1, fingerprint: String(i) }),
    );
    const md = renderSummary(result(many), { maxRows: 200 });
    expect(md).toContain('…and 50 more');
  });
});

describe('PR comment', () => {
  it('starts with the hidden marker and explains each finding', () => {
    const body = renderPrComment({ findings: [finding()], otherCount: 3 });
    expect(body.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(body).toContain('**Why:** No auth | found.');
    expect(body).toContain('3 more in files this PR did not change');
  });

  it('reports a clean PR', () => {
    expect(renderPrComment({ findings: [], otherCount: 0 })).toContain(
      'No issues found in the files changed',
    );
  });

  it('stays under the GitHub comment size limit', () => {
    const long = Array.from({ length: 50 }, (_, i) =>
      finding({ reason: 'x'.repeat(3000), fingerprint: String(i) }),
    );
    expect(renderPrComment({ findings: long, otherCount: 0 }).length).toBeLessThan(65_536);
  });
});

describe('upsertPrComment', () => {
  const repo = { owner: 'o', repo: 'r' };

  function fakeOctokit(existing: { id: number; body: string; user: { type: string } }[]) {
    const updateComment = vi.fn().mockResolvedValue({});
    const createComment = vi.fn().mockResolvedValue({});
    const octokit = {
      paginate: vi.fn().mockResolvedValue(existing),
      rest: { issues: { listComments: vi.fn(), updateComment, createComment } },
    } as unknown as Octokit;
    return { octokit, updateComment, createComment };
  }

  it('updates the existing bot comment instead of posting a new one', async () => {
    const { octokit, updateComment, createComment } = fakeOctokit([
      { id: 1, body: 'unrelated', user: { type: 'User' } },
      { id: 2, body: `${PR_COMMENT_MARKER} old`, user: { type: 'Bot' } },
    ]);
    expect(await upsertPrComment(octokit, repo, 7, 'new', { createIfMissing: true })).toBe(
      'updated',
    );
    expect(updateComment).toHaveBeenCalledWith({ ...repo, comment_id: 2, body: 'new' });
    expect(createComment).not.toHaveBeenCalled();
  });

  it('creates a comment only when asked to', async () => {
    const a = fakeOctokit([]);
    expect(await upsertPrComment(a.octokit, repo, 7, 'body', { createIfMissing: false })).toBe(
      'skipped',
    );
    expect(a.createComment).not.toHaveBeenCalled();

    const b = fakeOctokit([]);
    expect(await upsertPrComment(b.octokit, repo, 7, 'body', { createIfMissing: true })).toBe(
      'created',
    );
    expect(b.createComment).toHaveBeenCalledWith({ ...repo, issue_number: 7, body: 'body' });
  });

  it('falls back to a new comment when the marked one cannot be edited', async () => {
    const { octokit, updateComment, createComment } = fakeOctokit([
      { id: 3, body: `quoted ${PR_COMMENT_MARKER}`, user: { type: 'User' } },
    ]);
    updateComment.mockRejectedValue(Object.assign(new Error('forbidden'), { status: 403 }));
    expect(await upsertPrComment(octokit, repo, 7, 'body', { createIfMissing: true })).toBe(
      'created',
    );
    expect(createComment).toHaveBeenCalled();
  });
});

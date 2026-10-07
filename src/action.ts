import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { loadConfig } from './core/config.js';
import { scan } from './core/scanner.js';
import { countBySeverity, exceedsThreshold } from './core/severity.js';
import type { FailOn, Finding, ScanResult } from './core/types.js';
import {
  isStatus,
  listChangedFiles,
  uploadSarif,
  upsertPrComment,
  type Repo,
} from './github/api.js';
import { renderPrComment } from './reporters/pr-comment.js';
import { renderSarif } from './reporters/sarif.js';
import { renderSummary } from './reporters/summary.js';

const FAIL_ON = new Set(['high', 'medium', 'low', 'none']);
const MAX_ANNOTATIONS = 50;

function boolInput(name: string, fallback: boolean): boolean {
  const raw = core.getInput(name).trim().toLowerCase();
  if (raw === '') return fallback;
  if (['true', 'yes', '1'].includes(raw)) return true;
  if (['false', 'no', '0'].includes(raw)) return false;
  throw new Error(`Input "${name}" must be true or false, got "${raw}".`);
}

async function run(): Promise<void> {
  const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const root = path.resolve(workspace, core.getInput('path') || '.');

  const { config, source } = loadConfig(root, core.getInput('config') || undefined);
  if (source) core.info(`Using config ${path.relative(workspace, source)}`);

  const failOn = core.getInput('fail-on').trim();
  if (failOn) {
    if (!FAIL_ON.has(failOn)) throw new Error(`Input "fail-on" must be high, medium, low or none.`);
    config.failOn = failOn as FailOn;
  }
  if (boolInput('git-history', false)) {
    config.gitHistory = true;
    if (isShallow(root)) {
      core.warning(
        'git-history is enabled but the checkout is shallow, so only recent commits are scanned. Use actions/checkout with fetch-depth: 0.',
      );
    }
  }

  const scanned = await scan({ root, config });
  // Paths relative to the repository root, which is what GitHub expects.
  const prefix = path.relative(workspace, root).split(path.sep).join('/');
  const result: ScanResult = {
    ...scanned,
    findings: scanned.findings.map((f) => rebase(f, prefix)),
  };
  const counts = countBySeverity(result.findings);
  core.info(
    `leakroute: ${result.findings.length} possible issues (${counts.high} high, ${counts.medium} medium, ${counts.low} low) in ${result.filesScanned} files.`,
  );

  const sarif = renderSarif(result);
  const sarifPath = path.resolve(workspace, core.getInput('sarif-file') || 'leakroute.sarif');
  writeFileSync(sarifPath, sarif);

  core.setOutput('findings', result.findings.length);
  core.setOutput('high', counts.high);
  core.setOutput('medium', counts.medium);
  core.setOutput('low', counts.low);
  core.setOutput('sarif-file', sarifPath);

  if (boolInput('annotations', true)) annotate(result.findings);

  const { context } = github;
  const repo: Repo | null = process.env.GITHUB_REPOSITORY ? context.repo : null;
  const pr = context.payload.pull_request as
    { number: number; head?: { sha?: string } } | undefined;
  const server = context.serverUrl || 'https://github.com';
  const linkSha = pr?.head?.sha ?? context.sha;
  const linkBase =
    repo && linkSha ? `${server}/${repo.owner}/${repo.repo}/blob/${linkSha}/` : undefined;
  const runUrl = repo
    ? `${server}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`
    : undefined;

  await core.summary.addRaw(renderSummary(result, { linkBase })).write();

  const token = core.getInput('github-token');
  const octokit = token && repo ? github.getOctokit(token) : null;

  if (octokit && repo && pr && boolInput('comment-on-pr', true)) {
    await guarded('post the PR comment', 'pull-requests: write', async () => {
      const changed = await listChangedFiles(octokit, repo, pr.number);
      const inPr = result.findings.filter((f) => changed.has(f.file) && !f.commit);
      const body = renderPrComment({
        findings: inPr,
        otherCount: result.findings.length - inPr.length,
        linkBase,
        runUrl,
      });
      const outcome = await upsertPrComment(octokit, repo, pr.number, body, {
        createIfMissing: inPr.length > 0,
      });
      core.info(`PR comment ${outcome}.`);
    });
  }

  if (octokit && repo && boolInput('upload-sarif', true)) {
    await guarded('upload SARIF to Code Scanning', 'security-events: write', async () => {
      const id = await uploadSarif(octokit, repo, {
        commitSha: context.sha,
        ref: context.ref,
        sarif,
      });
      core.info(`SARIF uploaded to Code Scanning (id ${id ?? 'unknown'}).`);
    });
  }

  if (exceedsThreshold(result.findings, config.failOn)) {
    core.setFailed(
      `leakroute found issues at or above "${config.failOn}" severity. See the job summary for details.`,
    );
  }
}

/** Runs a GitHub API step, turning permission problems into warnings instead of failures. */
async function guarded(what: string, permission: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    if (isStatus(err, 403) || isStatus(err, 404)) {
      core.warning(
        `Could not ${what}: ${(err as Error).message}. Check that the workflow grants "${permission}". ` +
          'Pull requests from forks get a read-only token; for Code Scanning on private repositories, GitHub Advanced Security must be enabled.',
      );
      return;
    }
    throw err;
  }
}

function annotate(findings: readonly Finding[]): void {
  for (const f of findings.filter((x) => !x.commit).slice(0, MAX_ANNOTATIONS)) {
    const props = { title: f.title, file: f.file, startLine: f.line, startColumn: f.column };
    const message = `${f.reason}\n\nFix: ${f.remediation}`;
    if (f.severity === 'high') core.error(message, props);
    else if (f.severity === 'medium') core.warning(message, props);
    else core.notice(message, props);
  }
}

function rebase(f: Finding, prefix: string): Finding {
  return prefix && prefix !== '.' ? { ...f, file: path.posix.join(prefix, f.file) } : f;
}

function isShallow(root: string): boolean {
  try {
    return (
      execFileSync('git', ['rev-parse', '--is-shallow-repository'], {
        cwd: root,
        encoding: 'utf8',
      }).trim() === 'true'
    );
  } catch {
    return false;
  }
}

run().catch((err: unknown) => {
  core.setFailed(err instanceof Error ? err.message : String(err));
});

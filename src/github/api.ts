import { gzipSync } from 'node:zlib';
import type { getOctokit } from '@actions/github';
import { PR_COMMENT_MARKER } from '../reporters/pr-comment.js';

export type Octokit = ReturnType<typeof getOctokit>;

export interface Repo {
  owner: string;
  repo: string;
}

/** Files added or modified by a pull request (removed files can't have findings). */
export async function listChangedFiles(
  octokit: Octokit,
  repo: Repo,
  pullNumber: number,
): Promise<Set<string>> {
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    ...repo,
    pull_number: pullNumber,
    per_page: 100,
  });
  return new Set(files.filter((f) => f.status !== 'removed').map((f) => f.filename));
}

export type CommentResult = 'created' | 'updated' | 'skipped';

/**
 * Creates or updates our single PR comment, found by its hidden marker.
 * With `createIfMissing: false`, a clean result doesn't add noise to a PR that
 * never had findings, but an existing comment is still updated to say "all clear".
 */
export async function upsertPrComment(
  octokit: Octokit,
  repo: Repo,
  issueNumber: number,
  body: string,
  options: { createIfMissing: boolean },
): Promise<CommentResult> {
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    ...repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  const ours = comments.filter((c) => c.body?.includes(PR_COMMENT_MARKER));
  // Prefer a bot-authored one, so a user quoting the marker can't hijack the update.
  const existing = ours.find((c) => c.user?.type === 'Bot') ?? ours[0];

  if (existing) {
    try {
      await octokit.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
      return 'updated';
    } catch (err) {
      // Not ours to edit (e.g. posted by another user or token): fall through and create.
      if (!isStatus(err, 403) && !isStatus(err, 404)) throw err;
    }
  }
  if (!options.createIfMissing) return 'skipped';
  await octokit.rest.issues.createComment({ ...repo, issue_number: issueNumber, body });
  return 'created';
}

/** Uploads SARIF to Code Scanning. Returns the upload id. */
export async function uploadSarif(
  octokit: Octokit,
  repo: Repo,
  options: { commitSha: string; ref: string; sarif: string },
): Promise<string | undefined> {
  const response = await octokit.rest.codeScanning.uploadSarif({
    ...repo,
    commit_sha: options.commitSha,
    ref: options.ref,
    sarif: gzipSync(Buffer.from(options.sarif, 'utf8')).toString('base64'),
    tool_name: 'leakroute',
  });
  return response.data.id;
}

export function isStatus(err: unknown, status: number): boolean {
  return typeof err === 'object' && err !== null && (err as { status?: number }).status === status;
}

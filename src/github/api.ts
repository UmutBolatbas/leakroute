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
  // Only a comment the token itself posted counts as ours: a token with write
  // access can edit anyone's comment, so a person quoting the marker must not
  // have their comment overwritten.
  const login = await authenticatedLogin(octokit);
  const existing = comments.find(
    (c) =>
      c.body?.startsWith(PR_COMMENT_MARKER) &&
      (login ? c.user?.login === login : c.user?.type === 'Bot'),
  );

  if (existing) {
    try {
      await octokit.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
      return 'updated';
    } catch (err) {
      // Not ours to edit (e.g. another bot's comment): fall through and create.
      if (!isStatus(err, 403) && !isStatus(err, 404)) throw err;
    }
  }
  if (!options.createIfMissing) return 'skipped';
  await octokit.rest.issues.createComment({ ...repo, issue_number: issueNumber, body });
  return 'created';
}

/**
 * The login behind a personal access token. The workflow's GITHUB_TOKEN and
 * GitHub App tokens can't call this endpoint; their comments are posted by a bot.
 */
async function authenticatedLogin(octokit: Octokit): Promise<string | null> {
  try {
    return (await octokit.rest.users.getAuthenticated()).data.login;
  } catch {
    return null;
  }
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

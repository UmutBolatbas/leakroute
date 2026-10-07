# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in leakroute itself. Use GitHub's
private vulnerability reporting instead: open the repository's **Security** tab and click
**Report a vulnerability**.

Examples of what counts as a vulnerability in leakroute:

- any way a detected secret ends up unredacted in an output (terminal, JSON, SARIF, job summary,
  PR comment, baseline, logs);
- the GitHub Action leaking its token or acting on a repository it shouldn't;
- code execution or path traversal triggered by scanning a crafted repository.

A missed detection or a false positive is not a vulnerability; please open a regular issue
for those (without real secrets in it).

You can expect an acknowledgement within a week. Fixes for confirmed issues are released as
soon as possible and credited in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

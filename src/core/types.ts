export type Severity = 'high' | 'medium' | 'low';
export type FailOn = Severity | 'none';
export type Category = 'endpoint' | 'secret';

/**
 * A single reported issue.
 *
 * There is deliberately no field that can hold a raw secret value. Secret rules
 * must call `redact()` at the point of detection and only store the masked form,
 * so no reporter can leak a secret even by accident.
 */
export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  /** Repo-relative path with forward slashes. */
  file: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** Short title, e.g. "Possible OpenAI API key". */
  title: string;
  /** Why this was flagged. Static analysis is never certain, so this is always explained. */
  reason: string;
  /** Suggested fix. */
  remediation: string;
  /** Stable identifier used for baselines and SARIF deduplication. Never derived from a secret. */
  fingerprint: string;
  /** Masked secret, e.g. "sk-a****". Only set for secret findings. */
  redactedValue?: string;
  /** Set when the finding comes from git history rather than the working tree. */
  commit?: string;
}

export interface SourceFile {
  /** Repo-relative path with forward slashes. */
  path: string;
  absPath: string;
  content: string;
}

export interface ScanStats {
  filesScanned: number;
  durationMs: number;
}

export interface ScanResult extends ScanStats {
  findings: Finding[];
  /** Source files that could not be parsed, so endpoint rules did not see them. */
  unparsedFiles: string[];
}

import type { Finding, ScanResult, Severity } from '../core/types.js';
import { DOCS_URL, RULES, ruleMeta } from '../rules/registry.js';
import { TOOL_NAME, VERSION } from '../version.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/** GitHub Code Scanning maps this rule property to Critical/High/Medium/Low. */
const SECURITY_SEVERITY: Record<Severity, string> = { high: '8.0', medium: '5.5', low: '3.0' };

/**
 * SARIF 2.1.0 for GitHub Code Scanning. Messages contain the finding's reason and
 * remediation; secrets appear only in their redacted form, as everywhere else.
 */
export function renderSarif(result: ScanResult): string {
  const usedRuleIds = [...new Set(result.findings.map((f) => f.ruleId))];
  // Declare every rule (not just the ones that fired) so Code Scanning can show
  // a rule as fixed when its last alert disappears.
  const ruleIds = [...new Set([...RULES.keys(), ...usedRuleIds])];
  const ruleIndex = new Map(ruleIds.map((id, i) => [id, i]));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            semanticVersion: VERSION,
            informationUri: 'https://github.com/UmutBolatbas/leakroute',
            rules: ruleIds.map((id) => {
              const meta = ruleMeta(id);
              return {
                id,
                name: toPascalCase(id),
                shortDescription: { text: meta.title },
                fullDescription: { text: meta.description },
                helpUri: DOCS_URL,
                help: { text: meta.description, markdown: meta.description },
                defaultConfiguration: { level: LEVEL[meta.defaultSeverity] },
                properties: {
                  tags: ['security', meta.category === 'secret' ? 'secrets' : 'authentication'],
                  precision: meta.category === 'secret' ? 'high' : 'medium',
                  'security-severity': SECURITY_SEVERITY[meta.defaultSeverity],
                },
              };
            }),
          },
        },
        results: result.findings.map((f) => toResult(f, ruleIndex.get(f.ruleId) ?? 0)),
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function toResult(f: Finding, ruleIndex: number) {
  const history = f.commit ? ` (found in git history, commit ${f.commit.slice(0, 12)})` : '';
  return {
    ruleId: f.ruleId,
    ruleIndex,
    level: LEVEL[f.severity],
    message: { text: `${f.title}${history}. ${f.reason} Fix: ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: encodeUri(f.file), uriBaseId: '%SRCROOT%' },
          region: { startLine: f.line, startColumn: f.column },
        },
      },
    ],
    partialFingerprints: { 'leakroute/v1': f.fingerprint },
    properties: { severity: f.severity, category: f.category },
  };
}

function encodeUri(file: string): string {
  return file.split('/').map(encodeURIComponent).join('/');
}

function toPascalCase(id: string): string {
  return id
    .split(/[/-]/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

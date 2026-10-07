export { scan, type ScanOptions } from './core/scanner.js';
export { loadConfig, defaultConfig, ConfigError, type ResolvedConfig } from './core/config.js';
export { exceedsThreshold, countBySeverity } from './core/severity.js';
export { redact } from './core/redact.js';
export type { Finding, ScanResult, Severity, FailOn, Category } from './core/types.js';
export { renderJson } from './reporters/json.js';
export { renderTerminal } from './reporters/terminal.js';
export { VERSION } from './version.js';

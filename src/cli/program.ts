import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { Command, InvalidArgumentError, Option } from 'commander';
import { ConfigError, loadConfig } from '../core/config.js';
import { scan } from '../core/scanner.js';
import { exceedsThreshold } from '../core/severity.js';
import type { FailOn } from '../core/types.js';
import { renderJson } from '../reporters/json.js';
import { renderTerminal } from '../reporters/terminal.js';
import { TOOL_NAME, VERSION } from '../version.js';

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Whether stdout supports colour. */
  color: boolean;
}

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

const FORMATS = ['text', 'json'] as const;
const FAIL_ON = ['high', 'medium', 'low', 'none'] as const;

interface ScanFlags {
  format: (typeof FORMATS)[number];
  output?: string;
  failOn?: FailOn;
  config?: string;
  gitHistory?: boolean;
  secrets: boolean;
  endpoints: boolean;
  color: boolean;
}

/** Runs the CLI and resolves to the process exit code. */
export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  let exitCode = EXIT_OK;

  const program = new Command()
    .name(TOOL_NAME)
    .description('Find unprotected API endpoints and leaked secrets.')
    .version(VERSION)
    .exitOverride()
    .configureOutput({ writeOut: io.stdout, writeErr: io.stderr });

  program
    .command('scan')
    .description('Scan a directory (default: current directory)')
    .argument('[path]', 'directory to scan', '.')
    .addOption(
      new Option('-f, --format <format>', 'output format').choices(FORMATS).default('text'),
    )
    .option('-o, --output <file>', 'write the report to a file instead of stdout')
    .addOption(
      new Option(
        '--fail-on <level>',
        'exit with code 1 when a finding has at least this severity',
      ).choices(FAIL_ON),
    )
    .option(
      '-c, --config <file>',
      'path to a config file (default: .leakroute.yml in the scanned directory)',
    )
    .option('--git-history', 'also scan every commit in git history for secrets (slow)')
    .option('--no-secrets', 'skip secret detection')
    .option('--no-endpoints', 'skip endpoint analysis')
    .option('--no-color', 'disable coloured output')
    .action(async (target: string, flags: ScanFlags) => {
      exitCode = await runScan(target, flags, io);
    });

  try {
    await program.parseAsync(['node', TOOL_NAME, ...argv]);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'commander.helpDisplayed' || code === 'commander.version') return EXIT_OK;
    if (code?.startsWith('commander.')) return EXIT_ERROR;
    if (err instanceof ConfigError || err instanceof InvalidArgumentError) {
      io.stderr(`${TOOL_NAME}: ${err.message}\n`);
      return EXIT_ERROR;
    }
    io.stderr(`${TOOL_NAME}: ${(err as Error).stack ?? String(err)}\n`);
    return EXIT_ERROR;
  }
  return exitCode;
}

async function runScan(target: string, flags: ScanFlags, io: CliIo): Promise<number> {
  const root = path.resolve(target);
  const { config } = loadConfig(root, flags.config);

  // CLI flags win over the config file.
  if (flags.failOn) config.failOn = flags.failOn;
  if (flags.gitHistory) config.gitHistory = true;
  if (!flags.secrets) config.scan.secrets = false;
  if (!flags.endpoints) config.scan.endpoints = false;

  const result = await scan({ root, config });

  const report =
    flags.format === 'json'
      ? renderJson(result)
      : renderTerminal(result, { color: flags.color && io.color && !flags.output });

  if (flags.output) {
    writeFileSync(path.resolve(flags.output), `${report}\n`);
    io.stderr(`Report written to ${flags.output}\n`);
  } else {
    io.stdout(`${report}\n`);
  }

  return exceedsThreshold(result.findings, config.failOn) ? EXIT_FINDINGS : EXIT_OK;
}

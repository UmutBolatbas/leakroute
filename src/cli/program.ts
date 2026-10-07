import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Command, InvalidArgumentError, Option } from 'commander';
import { writeBaseline } from '../core/baseline.js';
import { ConfigError, DEFAULT_BASELINE, loadConfig, type ResolvedConfig } from '../core/config.js';
import { scan } from '../core/scanner.js';
import { exceedsThreshold } from '../core/severity.js';
import type { FailOn } from '../core/types.js';
import { renderJson } from '../reporters/json.js';
import { renderSarif } from '../reporters/sarif.js';
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

const FORMATS = ['text', 'json', 'sarif'] as const;
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
  /** A path, `false` for --no-baseline, or undefined to use the config. */
  baseline?: string | false;
}

interface BaselineFlags {
  config?: string;
  output?: string;
  gitHistory?: boolean;
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
    .option(
      '--baseline <file>',
      `only report findings not in this baseline (default: ${DEFAULT_BASELINE})`,
    )
    .option('--no-baseline', 'report every finding, even those in the baseline')
    .option('--no-secrets', 'skip secret detection')
    .option('--no-endpoints', 'skip endpoint analysis')
    .option('--no-color', 'disable coloured output')
    .action(async (target: string, flags: ScanFlags) => {
      exitCode = await runScan(target, flags, io);
    });

  program
    .command('baseline')
    .description('Record current findings so later scans only report new ones')
    .argument('[path]', 'directory to scan', '.')
    .option('-c, --config <file>', 'path to a config file')
    .option(
      '-o, --output <file>',
      `baseline file to write (default: ${DEFAULT_BASELINE} in the scanned directory)`,
    )
    .option('--git-history', 'include secrets found in git history')
    .action(async (target: string, flags: BaselineFlags) => {
      exitCode = await runBaseline(target, flags, io);
    });

  program
    .command('init')
    .description('Create a commented .leakroute.yml')
    .argument('[path]', 'directory to create it in', '.')
    .option('--force', 'overwrite an existing file')
    .action((target: string, flags: { force?: boolean }) => {
      exitCode = runInit(target, flags, io);
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
  applyBaselineFlag(config, flags.baseline);

  const result = await scan({ root, config });

  const report =
    flags.format === 'json'
      ? renderJson(result)
      : flags.format === 'sarif'
        ? renderSarif(result)
        : renderTerminal(result, { color: flags.color && io.color && !flags.output });

  if (flags.output) {
    writeFileSync(path.resolve(flags.output), `${report}\n`);
    io.stderr(`Report written to ${flags.output}\n`);
  } else {
    io.stdout(`${report}\n`);
  }

  return exceedsThreshold(result.findings, config.failOn) ? EXIT_FINDINGS : EXIT_OK;
}

function applyBaselineFlag(config: ResolvedConfig, flag: string | false | undefined): void {
  if (flag === false) config.baseline = null;
  else if (typeof flag === 'string') config.baseline = path.resolve(flag);
}

async function runBaseline(target: string, flags: BaselineFlags, io: CliIo): Promise<number> {
  const root = path.resolve(target);
  const { config } = loadConfig(root, flags.config);
  if (flags.gitHistory) config.gitHistory = true;

  const result = await scan({ root, config, useBaseline: false });
  const file = path.resolve(root, flags.output ?? config.baseline ?? DEFAULT_BASELINE);
  const count = writeBaseline(file, result.findings);
  const shown = path.relative(process.cwd(), file) || file;
  io.stdout(
    `Recorded ${count} ${count === 1 ? 'finding' : 'findings'} in ${shown}.\n` +
      'Commit this file: from now on only new findings are reported. ' +
      'Findings silenced with leakroute-ignore are not included.\n',
  );
  return EXIT_OK;
}

const CONFIG_TEMPLATE = `# leakroute configuration. Every key is optional.
# Docs: https://github.com/UmutBolatbas/leakroute#configuration

# Fail when a finding has at least this severity: high | medium | low | none
fail-on: high

scan:
  endpoints: true
  secrets: true

# Your own auth middleware / decorator / dependency names (added to the built-in list).
auth-middleware: []
#  - requireAdmin
#  - withSession

# Routes that are public on purpose (glob patterns).
public-routes: []
#  - /api/webhooks/*

# Paths to skip (glob patterns, relative to this file).
ignore-paths:
  - '**/tests/**'
  - '**/fixtures/**'

# Rules to turn off, by id or glob, e.g. secret/jwt or endpoint/*.
disable-rules: []
`;

function runInit(target: string, flags: { force?: boolean }, io: CliIo): number {
  const file = path.resolve(target, '.leakroute.yml');
  if (existsSync(file) && !flags.force) {
    io.stderr(`${TOOL_NAME}: ${file} already exists (use --force to overwrite).\n`);
    return EXIT_ERROR;
  }
  writeFileSync(file, CONFIG_TEMPLATE);
  io.stdout(`Created ${path.relative(process.cwd(), file) || file}.\n`);
  return EXIT_OK;
}

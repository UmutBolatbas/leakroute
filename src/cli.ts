#!/usr/bin/env node
import pc from 'picocolors';
import { run } from './cli/program.js';

const exitCode = await run(process.argv.slice(2), {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  color: pc.isColorSupported,
});
process.exitCode = exitCode;

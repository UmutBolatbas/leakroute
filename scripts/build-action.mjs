// Bundles the GitHub Action into dist/ with ncc and copies the WASM files it loads at runtime.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Copies bytes only. copyFileSync keeps the source's mode, and npm ships
// web-tree-sitter.wasm as executable, so on Linux git would see a mode change
// and the CI freshness check would fail.
function copyBytes(from, to) {
  writeFileSync(to, readFileSync(from));
}

rmSync('dist', { recursive: true, force: true });
execFileSync(
  process.execPath,
  [
    require.resolve('@vercel/ncc/dist/ncc/cli.js'),
    'build',
    'src/action.ts',
    '-o',
    'dist',
    '--license',
    'licenses.txt',
    '--quiet',
  ],
  { stdio: 'inherit' },
);

// The bundle is an ES module, but the TypeScript compiler (bundled for
// typescript-estree) is CommonJS and reads __filename/__dirname.
const shim = [
  "import { fileURLToPath as __leakrouteFileURLToPath } from 'node:url';",
  "import { dirname as __leakrouteDirname } from 'node:path';",
  'const __filename = __leakrouteFileURLToPath(import.meta.url);',
  'const __dirname = __leakrouteDirname(__filename);',
  '',
].join('\n');
let bundle = shim + readFileSync('dist/index.js', 'utf8');

// web-tree-sitter does `const { createRequire } = await import("module")`. Webpack
// rewrites that into an interop namespace without the named export, so put the
// native dynamic import back. Fail loudly if the pattern ever changes.
const brokenImport =
  /const \{ createRequire \} = await Promise\.resolve\(\/\* import\(\) \*\/\)\.then\(__nccwpck_require__\.t\.bind\(__nccwpck_require__, \d+, \d+\)\);/g;
const fixes = bundle.match(brokenImport)?.length ?? 0;
if (fixes !== 1) {
  throw new Error(`Expected one web-tree-sitter dynamic import to patch, found ${fixes}.`);
}
bundle = bundle.replace(brokenImport, 'const { createRequire } = await import("node:module");');
writeFileSync('dist/index.js', bundle);

// We load the WASM files ourselves (see src/parsers/python.ts); drop any copy ncc
// emitted under a hashed name so dist/ only holds what is used.
for (const file of readdirSync('dist')) {
  if (/^[0-9a-f]{20}\.wasm$/.test(file)) rmSync(`dist/${file}`);
}
copyBytes(require.resolve('web-tree-sitter/web-tree-sitter.wasm'), 'dist/web-tree-sitter.wasm');
copyBytes('vendor/grammars/tree-sitter-python.wasm', 'dist/tree-sitter-python.wasm');

// License texts that ncc's licenses.txt does not include: the vendored grammar
// (not an npm dependency) and TypeScript's third-party notice file (Apache-2.0).
copyBytes('vendor/grammars/LICENSE-tree-sitter-python', 'dist/LICENSE-tree-sitter-python');
copyBytes(
  require.resolve('typescript/ThirdPartyNoticeText.txt'),
  'dist/typescript-ThirdPartyNoticeText.txt',
);
console.log('Built dist/ for the GitHub Action.');

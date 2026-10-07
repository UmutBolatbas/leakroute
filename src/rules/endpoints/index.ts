import type { ResolvedConfig } from '../../core/config.js';
import { createPublicRouteMatcher } from '../../core/risk.js';
import type { Finding, SourceFile } from '../../core/types.js';
import { isJsFile, parseJs, type ParsedJs } from '../../parsers/javascript.js';
import { getPythonParser, isPythonFile, parsePython, type ParsedPy } from '../../parsers/python.js';
import { isTestLikePath } from '../secrets/placeholder.js';
import { createAuthMatcher } from './auth.js';
import { analyzeExpressFastify } from './express.js';
import { collectModuleInfo, type ModuleInfo } from './modules.js';
import { analyzeNextjs } from './nextjs.js';
import { PythonAnalyzer } from './python.js';
import type { EndpointContext, JsProject } from './types.js';

/** True for files the endpoint analyzers want to read. */
export function wantsForEndpoints(path: string): boolean {
  return (isJsFile(path) || isPythonFile(path)) && !isTestLikePath(path);
}

/**
 * Runs every endpoint analyzer over the project's source files.
 * Files that fail to parse are skipped (and counted) rather than aborting the scan.
 */
export async function analyzeEndpoints(
  sources: readonly SourceFile[],
  config: ResolvedConfig,
): Promise<{ findings: Finding[]; unparsed: string[] }> {
  const ctx: EndpointContext = {
    isAuth: createAuthMatcher(config.authMiddleware),
    isPublic: createPublicRouteMatcher(config.publicRoutes),
  };

  const files: ParsedJs[] = [];
  const modules = new Map<string, ModuleInfo>();
  const unparsed: string[] = [];
  for (const source of sources) {
    if (!wantsForEndpoints(source.path) || !isJsFile(source.path)) continue;
    const parsed = parseJs(source);
    if (!parsed) {
      unparsed.push(source.path);
      continue;
    }
    files.push(parsed);
    modules.set(source.path, collectModuleInfo(parsed));
  }

  const project: JsProject = { files, modules, paths: new Set(sources.map((s) => s.path)) };
  const findings = [...analyzeExpressFastify(project, ctx), ...analyzeNextjs(project, ctx)];

  const pySources = sources.filter((s) => wantsForEndpoints(s.path) && isPythonFile(s.path));
  if (pySources.length > 0) findings.push(...(await analyzePython(pySources, ctx, unparsed)));

  return { findings, unparsed };
}

async function analyzePython(
  sources: readonly SourceFile[],
  ctx: EndpointContext,
  unparsed: string[],
): Promise<Finding[]> {
  const parser = await getPythonParser();
  const parsed: ParsedPy[] = [];
  try {
    for (const source of sources) {
      const tree = parsePython(parser, source);
      if (tree) parsed.push(tree);
      else unparsed.push(source.path);
    }
    return new PythonAnalyzer(parsed, ctx).findings();
  } finally {
    // Trees live in WASM memory and are not garbage collected.
    for (const p of parsed) p.tree.delete();
  }
}

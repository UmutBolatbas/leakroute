import type { ResolvedConfig } from '../../core/config.js';
import { createPublicRouteMatcher } from '../../core/risk.js';
import type { Finding, SourceFile } from '../../core/types.js';
import { isJsFile, parseJs, type ParsedJs } from '../../parsers/javascript.js';
import { isTestLikePath } from '../secrets/placeholder.js';
import { createAuthMatcher } from './auth.js';
import { analyzeExpressFastify } from './express.js';
import { collectModuleInfo, type ModuleInfo } from './modules.js';
import { analyzeNextjs } from './nextjs.js';
import type { EndpointContext, JsProject } from './types.js';

/** True for files the endpoint analyzers want to read. */
export function wantsForEndpoints(path: string): boolean {
  return isJsFile(path) && !isTestLikePath(path);
}

/**
 * Runs every endpoint analyzer over the project's source files.
 * Files that fail to parse are skipped (and counted) rather than aborting the scan.
 */
export function analyzeEndpoints(
  sources: readonly SourceFile[],
  config: ResolvedConfig,
): { findings: Finding[]; unparsed: string[] } {
  const ctx: EndpointContext = {
    isAuth: createAuthMatcher(config.authMiddleware),
    isPublic: createPublicRouteMatcher(config.publicRoutes),
  };

  const files: ParsedJs[] = [];
  const modules = new Map<string, ModuleInfo>();
  const unparsed: string[] = [];
  for (const source of sources) {
    if (!wantsForEndpoints(source.path)) continue;
    const parsed = parseJs(source);
    if (!parsed) {
      unparsed.push(source.path);
      continue;
    }
    files.push(parsed);
    modules.set(source.path, collectModuleInfo(parsed));
  }

  const project: JsProject = { files, modules, paths: new Set(sources.map((s) => s.path)) };
  return {
    findings: [...analyzeExpressFastify(project, ctx), ...analyzeNextjs(project, ctx)],
    unparsed,
  };
}

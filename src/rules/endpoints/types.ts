import type { ParsedJs } from '../../parsers/javascript.js';
import type { AuthMatcher } from './auth.js';
import type { ModuleInfo } from './modules.js';

export interface EndpointContext {
  isAuth: AuthMatcher;
  isPublic: (routePath: string) => boolean;
}

export interface JsProject {
  files: readonly ParsedJs[];
  modules: ReadonlyMap<string, ModuleInfo>;
  /** All scanned file paths, for import resolution. */
  paths: ReadonlySet<string>;
}

import type { HttpMethod } from '../../core/risk.js';
import { pyArgs, pyString, pyStringList, type PyNode } from '../../parsers/python.js';

export const FASTAPI_CONSTRUCTORS: ReadonlySet<string> = new Set(['FastAPI', 'APIRouter']);

const METHODS: Record<string, HttpMethod> = {
  get: 'GET',
  post: 'POST',
  put: 'PUT',
  patch: 'PATCH',
  delete: 'DELETE',
  head: 'HEAD',
  options: 'OPTIONS',
};

/** `@router.post("/items")`, `@app.api_route("/x", methods=["GET", "POST"])`. */
export function fastapiRouteFromDecorator(
  attribute: string,
  call: PyNode,
): { methods: HttpMethod[]; path: string } | null {
  const args = pyArgs(call);
  const path = pyString(args.positional[0] ?? args.keywords.get('path')) ?? '(dynamic path)';
  const single = METHODS[attribute];
  if (single) return { methods: [single], path };
  if (attribute === 'api_route') {
    const methods = pyStringList(args.keywords.get('methods'))
      .map((m) => METHODS[m.toLowerCase()])
      .filter((m): m is HttpMethod => m !== undefined);
    return { methods: methods.length > 0 ? methods : ['GET'], path };
  }
  return null;
}

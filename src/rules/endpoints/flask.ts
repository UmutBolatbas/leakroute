import type { HttpMethod } from '../../core/risk.js';
import { pyArgs, pyString, pyStringList, type PyNode } from '../../parsers/python.js';

export const FLASK_CONSTRUCTORS: ReadonlySet<string> = new Set(['Flask', 'Blueprint', 'Quart']);

const SHORTCUTS: Record<string, HttpMethod> = {
  get: 'GET',
  post: 'POST',
  put: 'PUT',
  patch: 'PATCH',
  delete: 'DELETE',
};

/** `@app.route("/x", methods=["POST"])` and the Flask 2 shortcuts `@bp.post("/x")`. */
export function flaskRouteFromDecorator(
  attribute: string,
  call: PyNode,
): { methods: HttpMethod[]; path: string } | null {
  const args = pyArgs(call);
  const path = pyString(args.positional[0] ?? args.keywords.get('rule')) ?? '(dynamic path)';
  const shortcut = SHORTCUTS[attribute];
  if (shortcut) return { methods: [shortcut], path };
  if (attribute !== 'route') return null;
  const methods = pyStringList(args.keywords.get('methods'))
    .map((m) => m.toUpperCase())
    .filter((m): m is HttpMethod =>
      ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(m),
    );
  return { methods: methods.length > 0 ? methods : ['GET'], path };
}

import type { Node, TSESTree } from '../../parsers/javascript.js';
import { stringValue, unwrap } from '../../parsers/javascript.js';
import type { Guard } from './express.js';

/** Fastify lifecycle hooks that run before the handler and can reject a request. */
export const FASTIFY_AUTH_HOOKS: ReadonlySet<string> = new Set([
  'onRequest',
  'preParsing',
  'preValidation',
  'preHandler',
]);

/**
 * Reads the auth-relevant parts of Fastify route options:
 * `{ onRequest: [fastify.authenticate], preHandler: fastify.auth([...]), handler }`.
 */
export function fastifyOptionGuards(
  options: Node,
  guardsFrom: (node: Node) => Guard[],
): { guards: Guard[]; handler: Node | undefined } {
  const obj = unwrap(options);
  const guards: Guard[] = [];
  let handler: Node | undefined;
  if (obj.type !== 'ObjectExpression') return { guards, handler };

  for (const prop of (obj as TSESTree.ObjectExpression).properties) {
    if (prop.type !== 'Property') continue;
    const key = prop.key.type === 'Identifier' ? prop.key.name : stringValue(prop.key);
    if (key === 'handler') handler = prop.value;
    else if (key && FASTIFY_AUTH_HOOKS.has(key)) guards.push(...guardsFrom(prop.value));
  }
  return { guards, handler };
}

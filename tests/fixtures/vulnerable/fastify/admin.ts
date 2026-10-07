import type { FastifyInstance } from 'fastify';

export default async function adminRoutes(fastify: FastifyInstance) {
  fastify.get('/dashboard', async () => ({ ok: true })); // expect: endpoint/fastify-unprotected-route
}

import type { FastifyInstance } from 'fastify';

export default async function privateRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', async (request) => {
    await request.jwtVerify();
  });
  fastify.get('/notes', async () => []);
}

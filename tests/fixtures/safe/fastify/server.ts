import Fastify from 'fastify';
import jwt from '@fastify/jwt';
import privateRoutes from './private';

const fastify = Fastify();
fastify.register(jwt, { secret: process.env.JWT_SECRET as string });

fastify.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch {
    reply.code(401).send();
  }
});

fastify.get('/health', async () => 'ok');
fastify.get('/api/me', { onRequest: [fastify.authenticate] }, async (req) => req.user);
fastify.post('/api/items', { preHandler: fastify.auth([fastify.verifyJWT]) }, async () => ({}));
fastify.route({
  method: 'DELETE',
  url: '/api/items/:id',
  onRequest: fastify.authenticate,
  handler: async () => ({}),
});

// Encapsulated plugin with an auth hook: every route inside is protected.
fastify.register(
  async (instance) => {
    instance.addHook('onRequest', instance.authenticate);
    instance.get('/reports', async () => []);
    instance.post('/reports', async () => ({}));
  },
  { prefix: '/v1' },
);

fastify.register(privateRoutes, { prefix: '/private' });

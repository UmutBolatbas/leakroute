import Fastify from 'fastify';
import adminRoutes from './admin';

const fastify = Fastify({ logger: true });

fastify.get('/api/orders', async () => []); // expect: endpoint/fastify-unprotected-route
fastify.post('/api/orders', { schema: { body: {} } }, async (req) => req.body); // expect: endpoint/fastify-unprotected-route
fastify.route({ method: ['PUT', 'DELETE'], url: '/api/orders/:id', handler: async () => ({}) }); // expect: endpoint/fastify-unprotected-route expect: endpoint/fastify-unprotected-route
fastify.get('/healthz', async () => 'ok');

fastify.register(adminRoutes, { prefix: '/admin' });

fastify.listen({ port: 3000 });

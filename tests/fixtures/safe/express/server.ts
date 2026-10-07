import express from 'express';
import passport from 'passport';
import axios from 'axios';
import { authenticate } from './middleware/auth';
import { checkSession } from './middleware/session';
import accountRouter from './routes/account';
import { createOrder } from './controllers/orders';

const app = express();
const api = axios.create({ baseURL: 'https://example.com' });

app.get('/health', (_req, res) => res.send('ok'));
app.post('/auth/register', (_req, res) => res.sendStatus(201));
app.get('/', (_req, res) => res.send('home'));

// Route-level middleware
app.post('/api/posts', authenticate, (req, res) => res.json(req.body));
app.get('/api/feed', passport.authenticate('jwt', { session: false }), (_req, res) => res.json([]));

// Middleware with a non-standard name that is recognised by what it does
app.delete('/api/sessions/:id', checkSession, (_req, res) => res.sendStatus(204));

// Inline check inside the handler
app.patch('/api/profile', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  res.json(req.user);
});

// Imported handler that verifies the token itself
app.post('/api/orders', createOrder);

// Router protected where it is mounted
app.use('/api/account', authenticate, accountRouter);

// Not an Express app: an HTTP client with the same method names
export async function loadUsers() {
  await api.get('/users', { params: { page: 1 } });
  await api.post('/users', { name: 'x' });
}

// Everything below is protected by app-level middleware
app.use(authenticate);
app.delete('/api/admin/users/:id', (_req, res) => res.sendStatus(204));

app.listen(3000);

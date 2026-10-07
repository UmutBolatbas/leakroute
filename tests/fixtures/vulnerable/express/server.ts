import express from 'express';
import { requireAuth } from './middleware/auth';
import adminRouter from './routes/admin';
import usersRouter from './routes/users';

const app = express();
app.use(express.json());

app.get('/health', (_req, res) => res.send('ok'));
app.post('/login', (_req, res) => res.json({ token: 'issued' }));

app.post('/api/feedback', async (req, res) => { // expect: endpoint/express-unprotected-route
  res.status(201).json(req.body);
});
app.get('/api/products', (_req, res) => res.json([])); // expect: endpoint/express-unprotected-route

app.use('/admin', adminRouter);
app.use('/api/users', usersRouter);

// Registered after the routes above, so it does not protect them.
app.use(requireAuth);
app.get('/api/me', (req, res) => res.json(req.user));

app.listen(3000);

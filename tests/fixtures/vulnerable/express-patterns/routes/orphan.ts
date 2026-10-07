import { Router } from 'express';

// Exported but never mounted anywhere we can see.
export const orphan = Router();
orphan.post('/api/orphan', (_req, res) => res.sendStatus(201)); // expect: endpoint/express-unprotected-route

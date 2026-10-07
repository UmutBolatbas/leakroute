import { Router } from 'express';

const router = Router();
router.get('/', (req, res) => res.json(req.user));
router.delete('/', (_req, res) => res.sendStatus(204));
router.post('/billing', (_req, res) => res.sendStatus(200));

export default router;

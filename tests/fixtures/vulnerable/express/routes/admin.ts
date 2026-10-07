import { Router } from 'express';

const router = Router();

router.delete('/users/:id', async (req, res) => { // expect: endpoint/express-unprotected-route
  res.sendStatus(204);
});
router.get('/stats', (_req, res) => res.json({ users: 10 })); // expect: endpoint/express-unprotected-route

export default router;

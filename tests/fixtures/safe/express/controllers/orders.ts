import type { Request, Response } from 'express';
import { verifyToken } from '../lib/tokens';

export async function createOrder(req: Request, res: Response) {
  const user = await verifyToken(req.headers.authorization);
  res.status(201).json({ user });
}

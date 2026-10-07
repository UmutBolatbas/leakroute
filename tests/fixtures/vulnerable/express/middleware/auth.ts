import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).end();
  jwt.verify(token, process.env.JWT_SECRET as string);
  next();
}

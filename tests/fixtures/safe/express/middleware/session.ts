import type { NextFunction, Request, Response } from 'express';

export async function checkSession(req: Request, res: Response, next: NextFunction) {
  const session = await getSession(req);
  if (!session) return res.status(403).end();
  next();
}

async function getSession(_req: Request) {
  return null;
}

import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) { // expect: endpoint/nextjs-unprotected-api-route
  if (req.method !== 'POST') return res.status(405).end();
  res.json({ exported: true });
}
